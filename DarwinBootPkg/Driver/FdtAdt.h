// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef DARWIN_BOOT_FDT_ADT_H_
#define DARWIN_BOOT_FDT_ADT_H_

#include <Uefi.h>

//
// /chosen darwinboot-fdt (UINT32) asks DarwinBoot to fill in, from the firmware's flattened device tree, what the payload's
// Apple device tree cannot know ahead of the VM it boots in.
//
#define DARWIN_BOOT_FDT_MEMORY   BIT0   // /chosen dram-base, dram-size and what follows from the RAM's end
#define DARWIN_BOOT_FDT_DEVICES  BIT1   // the /arm-io nodes of the VM's virtio-mmio devices, its pools and its battery

/**
  Completes the Apple device tree in Tree from the firmware's flattened device tree, when /chosen asks for it.

  @param[in,out] Tree      The tree read from the payload; replaced by a new pool allocation when nodes are added.
  @param[in,out] TreeSize  Its size in bytes.

  @retval EFI_SUCCESS  The tree is complete (or did not ask for anything).
  @retval other        The tree asked for the FDT and it could not be completed: the firmware has no FDT, or the FDT lacks
                       the guest's RAM.
**/
EFI_STATUS
DarwinBootFdtAdt (
  IN OUT VOID   **Tree,
  IN OUT UINTN  *TreeSize
  );

#endif
