// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef DARWIN_BOOT_VIDEO_H_
#define DARWIN_BOOT_VIDEO_H_

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/GraphicsOutput.h>

STATIC
EFI_STATUS
DarwinBootVideoFromGop (CONST EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop, UINT64 Video[6])
{
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
  UINT64 RowBytes;
  UINT64 Bytes;

  ZeroMem (Video, 6 * sizeof (*Video));
  if ((Gop == NULL) || (Gop->Mode == NULL) || (Gop->Mode->Info == NULL) ||
      (Gop->Mode->SizeOfInfo < sizeof (*Info))) { return EFI_COMPROMISED_DATA; }
  Info = Gop->Mode->Info;
  if (Info->PixelFormat != PixelBlueGreenRedReserved8BitPerColor) { return EFI_UNSUPPORTED; }
  RowBytes = (UINT64)Info->PixelsPerScanLine * 4;
  if ((Info->HorizontalResolution == 0) || (Info->VerticalResolution == 0) ||
      (Info->PixelsPerScanLine < Info->HorizontalResolution) ||
      (Info->VerticalResolution > MAX_UINT64 / RowBytes)) { return EFI_COMPROMISED_DATA; }
  Bytes = RowBytes * Info->VerticalResolution;
  if ((Gop->Mode->FrameBufferBase == 0) || (Gop->Mode->FrameBufferBase & 3) ||
      (Gop->Mode->FrameBufferSize < Bytes) ||
      (Gop->Mode->FrameBufferBase > MAX_UINT64 - Gop->Mode->FrameBufferSize)) { return EFI_COMPROMISED_DATA; }
  Video[0] = Gop->Mode->FrameBufferBase;
  Video[1] = 1;
  Video[2] = RowBytes;
  Video[3] = Info->HorizontalResolution;
  Video[4] = Info->VerticalResolution;
  Video[5] = 32;
  return EFI_SUCCESS;
}

// A BLT-only GOP has no directly scanned framebuffer. Give XNU an explicitly reserved RAM
// image instead; its native display driver must import and present this image after EBS.
// This validates a handoff buffer, not a claim that the GOP supports direct pixel writes.
STATIC
EFI_STATUS
DarwinBootVideoFromBltGop (CONST EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop, UINT64 Base, UINT64 Capacity, UINT64 Video[6])
{
  CONST EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
  UINT64 RowBytes;

  ZeroMem (Video, 6 * sizeof (*Video));
  if ((Gop == NULL) || (Gop->Mode == NULL) || (Gop->Mode->Info == NULL) ||
      (Gop->Mode->SizeOfInfo < sizeof (*Info))) { return EFI_COMPROMISED_DATA; }
  Info = Gop->Mode->Info;
  if (Info->PixelFormat != PixelBltOnly) { return EFI_UNSUPPORTED; }
  if ((Base == 0) || (Base & (EFI_PAGE_SIZE - 1)) || (Capacity == 0) ||
      (Capacity & (EFI_PAGE_SIZE - 1)) || (Base > MAX_UINT64 - Capacity) ||
      (Info->HorizontalResolution == 0) || (Info->HorizontalResolution > 16384) ||
      (Info->VerticalResolution == 0) || (Info->VerticalResolution > 16384)) {
    return EFI_COMPROMISED_DATA;
  }
  RowBytes = ALIGN_VALUE ((UINT64)Info->HorizontalResolution * 4, 64);
  if (Info->VerticalResolution > Capacity / RowBytes) { return EFI_BUFFER_TOO_SMALL; }
  Video[0] = Base;
  Video[1] = 1;
  Video[2] = RowBytes;
  Video[3] = Info->HorizontalResolution;
  Video[4] = Info->VerticalResolution;
  Video[5] = 32;
  return EFI_SUCCESS;
}

#endif
