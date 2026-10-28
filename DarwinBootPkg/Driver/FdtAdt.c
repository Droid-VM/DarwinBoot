// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// The parts of the Apple device tree that belong to the VM rather than to the payload, taken at boot from the firmware's
// flattened device tree; make-droidvm-adt.py --dynamic writes the rest, and /chosen darwinboot-fdt says what to fill in.
// crosvm describes the VM in the FDT it hands the guest; a pseudo-unprotected VM's boot shim points /memory's first range
// at the guest's RAM before EDK2 runs; EDK2's FdtClientDxe serves that tree to drivers through FDT_CLIENT_PROTOCOL, which
// it installs whether or not the OS is offered a device tree (the configuration table is only for the latter).
//
//   DARWIN_BOOT_FDT_MEMORY   /chosen dram-base and dram-size from /memory. The values that follow from the end of RAM are
//                            recomputed as make-droidvm-adt.py computes them: /pram (the panic log, at the top of RAM),
//                            /chosen darwinboot-memory-limit (the panic region rounded down to 2 MiB, less the boot video
//                            reservation), darwinboot-video-memory (that reservation, just below the limit) and /defaults
//                            kern.maxvnodes (one vnode per 64 KiB of the kernel's memory, plus 1024). All in place.
//   DARWIN_BOOT_FDT_DEVICES  an /arm-io node per virtio-mmio window, by the device ID the window reports: a read-only disk
//                            is virtio-mmio-N (NativeVirtioBlock), the first writable one data-store, input devices input-N,
//                            then net, virtio-gpu (with drm-host-pool), virtio-snd and virtio-media-N (with media-host-pool),
//                            the pools being the FDT's droidvm,pool nodes; and battery for a google,goldfish-battery node.
//                            The nodes are the ones make-droidvm-adt.py writes, appended after /arm-io's own children.
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include "FdtAdt.h"

#define ARMIO_BASE       0x1000ULL
#define ARMIO_END        0x40000000ULL
#define MAX_WINDOWS      32
#define BUILDER_SIZE     SIZE_16KB
#define VIRTIO_MAGIC     0x74726976   // "virt"
#define VIRTIO_BLK_F_RO  BIT5

//
// EmbeddedPkg's FDT_CLIENT_PROTOCOL (Include/Protocol/FdtClient.h), member for member; Mu's basecore has no EmbeddedPkg.
//
typedef struct _DB_FDT_CLIENT DB_FDT_CLIENT;
typedef EFI_STATUS (EFIAPI *DB_FDT_GET_NODE_PROPERTY)(DB_FDT_CLIENT *This, INT32 Node, CONST CHAR8 *Name, CONST VOID **Prop, UINT32 *Size);
typedef EFI_STATUS (EFIAPI *DB_FDT_SET_NODE_PROPERTY)(DB_FDT_CLIENT *This, INT32 Node, CONST CHAR8 *Name, CONST VOID *Prop, UINT32 Size);
typedef EFI_STATUS (EFIAPI *DB_FDT_FIND_COMPATIBLE_NODE)(DB_FDT_CLIENT *This, CONST CHAR8 *Compatible, INT32 *Node);
typedef EFI_STATUS (EFIAPI *DB_FDT_FIND_NEXT_COMPATIBLE_NODE)(DB_FDT_CLIENT *This, CONST CHAR8 *Compatible, INT32 Previous, INT32 *Node);
typedef EFI_STATUS (EFIAPI *DB_FDT_FIND_COMPATIBLE_NODE_PROPERTY)(DB_FDT_CLIENT *This, CONST CHAR8 *Compatible, CONST CHAR8 *Name, CONST VOID **Prop, UINT32 *Size);
typedef EFI_STATUS (EFIAPI *DB_FDT_FIND_COMPATIBLE_NODE_REG)(DB_FDT_CLIENT *This, CONST CHAR8 *Compatible, CONST VOID **Reg, UINTN *AddressCells, UINTN *SizeCells, UINT32 *Size);
typedef EFI_STATUS (EFIAPI *DB_FDT_FIND_MEMORY_NODE_REG)(DB_FDT_CLIENT *This, INT32 *Node, CONST VOID **Reg, UINTN *AddressCells, UINTN *SizeCells, UINT32 *Size);
typedef EFI_STATUS (EFIAPI *DB_FDT_FIND_NEXT_MEMORY_NODE_REG)(DB_FDT_CLIENT *This, INT32 Previous, INT32 *Node, CONST VOID **Reg, UINTN *AddressCells, UINTN *SizeCells, UINT32 *Size);
typedef EFI_STATUS (EFIAPI *DB_FDT_GET_OR_INSERT_CHOSEN_NODE)(DB_FDT_CLIENT *This, INT32 *Node);
struct _DB_FDT_CLIENT {
  DB_FDT_GET_NODE_PROPERTY                GetNodeProperty;
  DB_FDT_SET_NODE_PROPERTY                SetNodeProperty;
  DB_FDT_FIND_COMPATIBLE_NODE             FindCompatibleNode;
  DB_FDT_FIND_NEXT_COMPATIBLE_NODE        FindNextCompatibleNode;
  DB_FDT_FIND_COMPATIBLE_NODE_PROPERTY    FindCompatibleNodeProperty;
  DB_FDT_FIND_COMPATIBLE_NODE_REG         FindCompatibleNodeReg;
  DB_FDT_FIND_MEMORY_NODE_REG             FindMemoryNodeReg;
  DB_FDT_FIND_NEXT_MEMORY_NODE_REG        FindNextMemoryNodeReg;
  DB_FDT_GET_OR_INSERT_CHOSEN_NODE        GetOrInsertChosenNode;
};
STATIC EFI_GUID  mFdtClientGuid = { 0xE11FACA0, 0x4710, 0x4C8E, { 0xA7, 0xA2, 0x01, 0xBA, 0xA2, 0x59, 0x1B, 0x4C } };

STATIC UINT32 U32 (CONST VOID *P) { return ReadUnaligned32 ((CONST UINT32 *)P); }
STATIC UINT64 U64 (CONST VOID *P) { return ReadUnaligned64 ((CONST UINT64 *)P); }
STATIC UINT64 Be64 (CONST VOID *P) { return SwapBytes64 (ReadUnaligned64 ((CONST UINT64 *)P)); }

//
// The Apple device tree: a node is a UINT32 property count, a UINT32 child count, its properties (a NUL-terminated name in
// 32 bytes, a UINT32 length, the value padded to 4 bytes), then its children.
//

// Moves *Offset past the properties of the node there; returns its child count through Children.
STATIC
BOOLEAN
AdtProperties (CONST UINT8 *Data, UINTN Size, UINTN *Offset, UINT32 *Children)
{
  UINT32 Properties;
  UINT32 Index;
  UINT32 Length;

  if ((*Offset > Size) || (Size - *Offset < 8)) { return FALSE; }
  Properties = U32 (Data + *Offset);
  *Children = U32 (Data + *Offset + 4);
  *Offset += 8;
  for (Index = 0; Index < Properties; Index++) {
    if (Size - *Offset < 36) { return FALSE; }
    Length = U32 (Data + *Offset + 32);
    *Offset += 36;
    if (Length > Size - *Offset) { return FALSE; }
    *Offset += Length;
    if (ALIGN_VALUE (*Offset, 4) > Size) { return FALSE; }
    *Offset = ALIGN_VALUE (*Offset, 4);
  }
  return TRUE;
}

// Moves *Offset past the whole subtree of the node there.
STATIC
BOOLEAN
AdtSkip (CONST UINT8 *Data, UINTN Size, UINTN *Offset, UINTN Depth)
{
  UINT32 Children;
  UINT32 Index;

  if ((Depth > 64) || !AdtProperties (Data, Size, Offset, &Children)) { return FALSE; }
  for (Index = 0; Index < Children; Index++) {
    if (!AdtSkip (Data, Size, Offset, Depth + 1)) { return FALSE; }
  }
  return TRUE;
}

// The value of property Name of the node at Node: its offset and length.
STATIC
BOOLEAN
AdtProperty (CONST UINT8 *Data, UINTN Size, UINTN Node, CONST CHAR8 *Name, UINTN *Value, UINT32 *Length)
{
  UINT32 Properties;
  UINT32 Index;
  UINT32 PropertyLength;
  UINTN  Offset;

  if ((Node > Size) || (Size - Node < 8)) { return FALSE; }
  Properties = U32 (Data + Node);
  Offset = Node + 8;
  for (Index = 0; Index < Properties; Index++) {
    if (Size - Offset < 36) { return FALSE; }
    PropertyLength = U32 (Data + Offset + 32);
    if (PropertyLength > Size - Offset - 36) { return FALSE; }
    if ((ScanMem8 (Data + Offset, 32, 0) != NULL) && (AsciiStrCmp ((CONST CHAR8 *)(Data + Offset), Name) == 0)) {
      *Value = Offset + 36;
      *Length = PropertyLength;
      return TRUE;
    }
    Offset = ALIGN_VALUE (Offset + 36 + PropertyLength, 4);
  }
  return FALSE;
}

// Whether the node at Node is called Name.
STATIC
BOOLEAN
AdtIsNamed (CONST UINT8 *Data, UINTN Size, UINTN Node, CONST CHAR8 *Name)
{
  UINTN  Value;
  UINT32 Length;

  return AdtProperty (Data, Size, Node, "name", &Value, &Length) && (Length == AsciiStrLen (Name) + 1) &&
         (CompareMem (Data + Value, Name, Length) == 0);
}

// The child of the node at Parent called Name.
STATIC
BOOLEAN
AdtChild (CONST UINT8 *Data, UINTN Size, UINTN Parent, CONST CHAR8 *Name, UINTN *Child)
{
  UINT32 Children;
  UINT32 Index;
  UINTN  Offset;

  Offset = Parent;
  if (!AdtProperties (Data, Size, &Offset, &Children)) { return FALSE; }
  for (Index = 0; Index < Children; Index++) {
    if (AdtIsNamed (Data, Size, Offset, Name)) { *Child = Offset; return TRUE; }
    if (!AdtSkip (Data, Size, &Offset, 1)) { return FALSE; }
  }
  return FALSE;
}

// Rewrites property Name of the node at Node in place, when it has exactly Length bytes.
STATIC
BOOLEAN
AdtSet (UINT8 *Data, UINTN Size, UINTN Node, CONST CHAR8 *Name, CONST VOID *Value, UINT32 Length)
{
  UINTN  At;
  UINT32 Have;

  if (!AdtProperty (Data, Size, Node, Name, &At, &Have) || (Have != Length)) { return FALSE; }
  CopyMem (Data + At, Value, Length);
  return TRUE;
}

//
// New nodes, written one after another into a buffer: a node's property count is raised as its properties are added.
//
typedef struct {
  UINT8    *Data;
  UINTN    Used;
  UINTN    Node;
  UINT32   Nodes;
  BOOLEAN  Overflow;
} ADT_BUILDER;

STATIC
VOID
Put (ADT_BUILDER *B, CONST VOID *Value, UINTN Length)
{
  if (B->Overflow || (Length > BUILDER_SIZE - B->Used)) { B->Overflow = TRUE; return; }
  CopyMem (B->Data + B->Used, Value, Length);
  B->Used += Length;
}

STATIC
VOID
AddProperty (ADT_BUILDER *B, CONST CHAR8 *Name, CONST VOID *Value, UINT32 Length)
{
  CHAR8  Key[32];
  UINT8  Zero[4];

  ZeroMem (Key, sizeof (Key));
  ZeroMem (Zero, sizeof (Zero));
  AsciiStrCpyS (Key, sizeof (Key), Name);
  Put (B, Key, sizeof (Key));
  Put (B, &Length, sizeof (Length));
  Put (B, Value, Length);
  Put (B, Zero, ALIGN_VALUE (Length, 4) - Length);
  if (!B->Overflow) { WriteUnaligned32 ((UINT32 *)(B->Data + B->Node), U32 (B->Data + B->Node) + 1); }
}

STATIC
VOID
AddString (ADT_BUILDER *B, CONST CHAR8 *Name, CONST CHAR8 *Value)
{
  AddProperty (B, Name, Value, (UINT32)AsciiStrLen (Value) + 1);
}

STATIC
VOID
AddPair (ADT_BUILDER *B, CONST CHAR8 *Name, UINT64 First, UINT64 Second)
{
  UINT64 Pair[2];

  Pair[0] = First;
  Pair[1] = Second;
  AddProperty (B, Name, Pair, sizeof (Pair));
}

STATIC
VOID
BeginNode (ADT_BUILDER *B, CONST CHAR8 *Name)
{
  UINT32 Header[2];

  Header[0] = 0;
  Header[1] = 0;
  B->Node = B->Used;
  Put (B, Header, sizeof (Header));
  AddString (B, "name", Name);
  B->Nodes++;
}

// A device node under /arm-io: its window relative to the arm-io base, and the pool it maps, if any.
STATIC
VOID
AddWindow (ADT_BUILDER *B, CONST CHAR8 *Name, CONST CHAR8 *Compatible, UINT64 Base, UINT64 Size, BOOLEAN Coherent,
           CONST CHAR8 *PoolName, CONST UINT64 *Pool)
{
  BeginNode (B, Name);
  AddString (B, "compatible", Compatible);
  AddPair (B, "reg", Base - ARMIO_BASE, Size);
  if (Coherent) { AddProperty (B, "dma-coherent", "", 0); }
  if ((PoolName != NULL) && (Pool[1] != 0)) { AddPair (B, PoolName, Pool[0], Pool[1]); }
}

//
// The FDT, through FDT_CLIENT_PROTOCOL. crosvm's root and /reserved-memory have two address and two size cells.
//
STATIC
BOOLEAN
FdtReg (DB_FDT_CLIENT *Fdt, INT32 Node, UINT64 *Base, UINT64 *Size)
{
  CONST VOID *Reg;
  UINT32     Length;

  if (EFI_ERROR (Fdt->GetNodeProperty (Fdt, Node, "reg", &Reg, &Length)) || (Length < 16)) { return FALSE; }
  *Base = Be64 (Reg);
  *Size = Be64 ((CONST UINT8 *)Reg + 8);
  return TRUE;
}

STATIC
EFI_STATUS
FillMemory (DB_FDT_CLIENT *Fdt, UINT8 *Data, UINTN Size, UINTN Chosen)
{
  INT32      Node;
  CONST VOID *Reg;
  UINTN      AddressCells;
  UINTN      SizeCells;
  UINT32     RegSize;
  UINT64     DramBase;
  UINT64     DramSize;
  UINT64     End;
  UINT64     Limit;
  UINT64     Kernel;
  UINT64     Pair[2];
  UINT32     Vnodes;
  UINTN      At;
  UINTN      Child;
  UINT32     Length;
  BOOLEAN    HasLimit;

  if (EFI_ERROR (Fdt->FindMemoryNodeReg (Fdt, &Node, &Reg, &AddressCells, &SizeCells, &RegSize)) ||
      (AddressCells != 2) || (SizeCells != 2) || (RegSize < 16)) {
    Print (L"DARWINBOOT: the firmware's FDT has no /memory\n");
    return EFI_NOT_FOUND;
  }
  // The boot shim puts the whole RAM window in the first range (crosvm droidvm-shim, Fdt::set_memory_window).
  DramBase = Be64 (Reg);
  DramSize = Be64 ((CONST UINT8 *)Reg + 8);
  if ((DramSize == 0) || ((DramBase | DramSize) & (SIZE_2MB - 1)) || (DramBase > MAX_UINT64 - DramSize)) {
    Print (L"DARWINBOOT: FDT /memory 0x%lx+0x%lx is no 2 MiB aligned RAM\n", DramBase, DramSize);
    return EFI_COMPROMISED_DATA;
  }
  if (!AdtSet (Data, Size, Chosen, "dram-base", &DramBase, 8) || !AdtSet (Data, Size, Chosen, "dram-size", &DramSize, 8)) {
    return EFI_COMPROMISED_DATA;
  }
  End = DramBase + DramSize;
  // The panic log: the top of RAM, its size as the payload chose it.
  if (AdtChild (Data, Size, 0, "pram", &Child) && AdtProperty (Data, Size, Child, "reg", &At, &Length) && (Length == 16)) {
    Pair[1] = U64 (Data + At + 8);
    if (Pair[1] >= DramSize) { return EFI_COMPROMISED_DATA; }
    Pair[0] = End - Pair[1];
    AdtSet (Data, Size, Child, "reg", Pair, sizeof (Pair));
    End = Pair[0];
  }
  // The kernel's memory ends at the panic region, below the boot video reservation when there is one.
  HasLimit = AdtProperty (Data, Size, Chosen, "darwinboot-memory-limit", &At, &Length) && (Length == 8);
  Limit = End & ~(UINT64)(SIZE_2MB - 1);
  if (HasLimit && AdtProperty (Data, Size, Chosen, "darwinboot-video-memory", &At, &Length) && (Length == 16)) {
    Pair[1] = U64 (Data + At + 8);
    if (Pair[1] >= Limit - DramBase) { return EFI_COMPROMISED_DATA; }
    Limit -= Pair[1];
    Pair[0] = Limit;
    AdtSet (Data, Size, Chosen, "darwinboot-video-memory", Pair, sizeof (Pair));
  }
  if (HasLimit) {
    AdtSet (Data, Size, Chosen, "darwinboot-memory-limit", &Limit, 8);
    Kernel = Limit - DramBase;
  } else if (AdtProperty (Data, Size, Chosen, "darwinboot-memory-size", &At, &Length) && (Length == 8)) {
    Kernel = U64 (Data + At);
  } else {
    Kernel = DramSize;
  }
  if (AdtChild (Data, Size, 0, "defaults", &Child)) {
    Vnodes = (UINT32)(Kernel / SIZE_64KB + 1024);
    AdtSet (Data, Size, Child, "kern.maxvnodes", &Vnodes, sizeof (Vnodes));
  }
  Print (L"DARWINBOOT: FDT RAM 0x%lx+0x%lx\n", DramBase, DramSize);
  return EFI_SUCCESS;
}

typedef struct {
  UINT64  Base;
  UINT64  Size;
  UINT32  Device;
  BOOLEAN ReadOnly;
} WINDOW;

STATIC
UINT32
Mmio32 (UINT64 Address)
{
  return *(volatile CONST UINT32 *)(UINTN)Address;
}

// The FDT's virtio-mmio windows, by address, each with the device it holds (0: none) and, for a disk, whether it is read-only.
STATIC
UINTN
FindWindows (DB_FDT_CLIENT *Fdt, WINDOW *Windows)
{
  INT32      Node;
  UINTN      Count;
  UINTN      Index;
  UINTN      Sorted;
  WINDOW     Window;
  EFI_STATUS Status;

  Count = 0;
  for (Status = Fdt->FindCompatibleNode (Fdt, "virtio,mmio", &Node); !EFI_ERROR (Status) && (Count < MAX_WINDOWS);
       Status = Fdt->FindNextCompatibleNode (Fdt, "virtio,mmio", Node, &Node)) {
    ZeroMem (&Window, sizeof (Window));
    if (!FdtReg (Fdt, Node, &Window.Base, &Window.Size) || (Window.Size < 0x100) || (Window.Base < ARMIO_BASE) ||
        (Window.Base > ARMIO_END - Window.Size)) { continue; }
    if ((Mmio32 (Window.Base) == VIRTIO_MAGIC) && (Mmio32 (Window.Base + 4) == 2)) {
      Window.Device = Mmio32 (Window.Base + 8);
      if (Window.Device == 2) {
        *(volatile UINT32 *)(UINTN)(Window.Base + 0x14) = 0;   // device features, bits 0..31
        Window.ReadOnly = (Mmio32 (Window.Base + 0x10) & VIRTIO_BLK_F_RO) != 0;
      }
    }
    for (Index = Count; (Index > 0) && (Windows[Index - 1].Base > Window.Base); Index--) {
      Windows[Index] = Windows[Index - 1];
    }
    Windows[Index] = Window;
    Count++;
  }
  for (Sorted = 1; Sorted < Count; Sorted++) {
    if (Windows[Sorted].Base == Windows[Sorted - 1].Base) { return 0; }   // one window, two nodes: no tree to trust
  }
  return Count;
}

// The droidvm,pool node called Name (its droidvm,pool-name), as an absolute GPA and a size.
STATIC
VOID
FindPool (DB_FDT_CLIENT *Fdt, CONST CHAR8 *Name, UINT64 Pool[2])
{
  INT32      Node;
  CONST VOID *Value;
  UINT32     Length;
  EFI_STATUS Status;

  Pool[0] = 0;
  Pool[1] = 0;
  for (Status = Fdt->FindCompatibleNode (Fdt, "droidvm,pool", &Node); !EFI_ERROR (Status);
       Status = Fdt->FindNextCompatibleNode (Fdt, "droidvm,pool", Node, &Node)) {
    if (EFI_ERROR (Fdt->GetNodeProperty (Fdt, Node, "droidvm,pool-name", &Value, &Length)) ||
        (Length != AsciiStrLen (Name) + 1) || (CompareMem (Value, Name, Length) != 0)) { continue; }
    if (!FdtReg (Fdt, Node, &Pool[0], &Pool[1])) { Pool[1] = 0; }
    return;
  }
}

STATIC
EFI_STATUS
FillDevices (DB_FDT_CLIENT *Fdt, VOID **Tree, UINTN *TreeSize)
{
  STATIC CONST CHAR8  *Taken[] = { "data-store", "net", "virtio-gpu", "virtio-snd", "battery", "input-0", "virtio-mmio-0", "virtio-media-0" };
  WINDOW       Windows[MAX_WINDOWS];
  ADT_BUILDER  B;
  UINT8        *Data;
  UINT8        *New;
  UINTN        Count;
  UINTN        Index;
  UINTN        ArmIo;
  UINTN        End;
  UINTN        Disks;
  UINTN        Inputs;
  UINTN        Media;
  BOOLEAN      Store;
  BOOLEAN      Net;
  BOOLEAN      Gpu;
  BOOLEAN      Sound;
  UINT64       DrmPool[2];
  UINT64       MediaPool[2];
  UINT64       Battery[2];
  INT32        Node;
  CHAR8        Name[32];

  Data = *Tree;
  if (!AdtChild (Data, *TreeSize, 0, "arm-io", &ArmIo)) { return EFI_COMPROMISED_DATA; }
  for (Index = 0; Index < ARRAY_SIZE (Taken); Index++) {
    if (AdtChild (Data, *TreeSize, ArmIo, Taken[Index], &End)) {
      Print (L"DARWINBOOT: /arm-io already has %a; the tree must not describe the devices it asks the FDT for\n", Taken[Index]);
      return EFI_COMPROMISED_DATA;
    }
  }
  End = ArmIo;
  if (!AdtSkip (Data, *TreeSize, &End, 1)) { return EFI_COMPROMISED_DATA; }
  Count = FindWindows (Fdt, Windows);
  FindPool (Fdt, "drm2kgsl_host", DrmPool);
  FindPool (Fdt, "media_host", MediaPool);
  Battery[1] = 0;
  if (!EFI_ERROR (Fdt->FindCompatibleNode (Fdt, "google,goldfish-battery", &Node)) && !FdtReg (Fdt, Node, &Battery[0], &Battery[1])) {
    Battery[1] = 0;
  }
  ZeroMem (&B, sizeof (B));
  B.Data = AllocatePool (BUILDER_SIZE);
  if (B.Data == NULL) { return EFI_OUT_OF_RESOURCES; }
  // In make-droidvm-adt.py's order: the read-only disks, the Data store, the input devices, net, the GPU, sound, media.
  Disks = 0;
  for (Index = 0; Index < Count; Index++) {
    if ((Windows[Index].Device != 2) || !Windows[Index].ReadOnly) { continue; }
    AsciiSPrint (Name, sizeof (Name), "virtio-mmio-%u", (UINT32)Disks++);
    AddWindow (&B, Name, "virtio,mmio", Windows[Index].Base, Windows[Index].Size, TRUE, NULL, NULL);
  }
  Store = FALSE;
  for (Index = 0; (Index < Count) && !Store; Index++) {
    if ((Windows[Index].Device != 2) || Windows[Index].ReadOnly) { continue; }
    AddWindow (&B, "data-store", "droidvm,data-store", Windows[Index].Base, Windows[Index].Size, TRUE, NULL, NULL);
    Store = TRUE;
  }
  Inputs = 0;
  for (Index = 0; Index < Count; Index++) {
    if (Windows[Index].Device != 18) { continue; }
    AsciiSPrint (Name, sizeof (Name), "input-%u", (UINT32)Inputs++);
    AddWindow (&B, Name, "droidvm,virtio-input", Windows[Index].Base, Windows[Index].Size, TRUE, NULL, NULL);
  }
  Net = Gpu = Sound = FALSE;
  for (Index = 0; Index < Count; Index++) {
    if ((Windows[Index].Device == 1) && !Net) {
      AddWindow (&B, "net", "droidvm,net", Windows[Index].Base, Windows[Index].Size, TRUE, NULL, NULL);
      Net = TRUE;
    }
  }
  for (Index = 0; Index < Count; Index++) {
    if ((Windows[Index].Device == 16) && !Gpu) {
      AddWindow (&B, "virtio-gpu", "droidvm,virtio-gpu", Windows[Index].Base, Windows[Index].Size, TRUE, "drm-host-pool", DrmPool);
      Gpu = TRUE;
    }
  }
  for (Index = 0; Index < Count; Index++) {
    if ((Windows[Index].Device == 25) && !Sound) {
      AddWindow (&B, "virtio-snd", "droidvm,virtio-snd", Windows[Index].Base, Windows[Index].Size, TRUE, NULL, NULL);
      Sound = TRUE;
    }
  }
  Media = 0;
  for (Index = 0; Index < Count; Index++) {
    if (Windows[Index].Device != 48) { continue; }
    AsciiSPrint (Name, sizeof (Name), "virtio-media-%u", (UINT32)Media++);
    AddWindow (&B, Name, "droidvm,virtio-media", Windows[Index].Base, Windows[Index].Size, TRUE, "media-host-pool", MediaPool);
  }
  if ((Battery[1] != 0) && (Battery[0] >= ARMIO_BASE) && (Battery[0] <= ARMIO_END - Battery[1])) {
    AddWindow (&B, "battery", "google,goldfish-battery", Battery[0], Battery[1], FALSE, NULL, NULL);
  }
  if (B.Overflow) { FreePool (B.Data); return EFI_BUFFER_TOO_SMALL; }
  New = AllocatePool (*TreeSize + B.Used);
  if (New == NULL) { FreePool (B.Data); return EFI_OUT_OF_RESOURCES; }
  CopyMem (New, Data, End);
  CopyMem (New + End, B.Data, B.Used);
  CopyMem (New + End + B.Used, Data + End, *TreeSize - End);
  WriteUnaligned32 ((UINT32 *)(New + ArmIo + 4), U32 (New + ArmIo + 4) + B.Nodes);
  Print (L"DARWINBOOT: FDT devices: %u disk(s)%a, %u input, %a%a%a%u media, pools drm 0x%lx+0x%lx media 0x%lx+0x%lx%a\n",
         (UINT32)Disks, Store ? " + data store" : "", (UINT32)Inputs, Net ? "net, " : "", Gpu ? "gpu, " : "",
         Sound ? "snd, " : "", (UINT32)Media, DrmPool[0], DrmPool[1], MediaPool[0], MediaPool[1], Battery[1] ? ", battery" : "");
  FreePool (B.Data);
  FreePool (*Tree);
  *Tree = New;
  *TreeSize += B.Used;
  return EFI_SUCCESS;
}

EFI_STATUS
DarwinBootFdtAdt (
  IN OUT VOID   **Tree,
  IN OUT UINTN  *TreeSize
  )
{
  DB_FDT_CLIENT  *Fdt;
  UINTN          Chosen;
  UINTN          At;
  UINT32         Length;
  UINT32         Ask;
  EFI_STATUS     Status;

  if (!AdtChild (*Tree, *TreeSize, 0, "chosen", &Chosen) ||
      !AdtProperty (*Tree, *TreeSize, Chosen, "darwinboot-fdt", &At, &Length)) { return EFI_SUCCESS; }
  if (Length != 4) { return EFI_COMPROMISED_DATA; }
  Ask = U32 ((UINT8 *)*Tree + At);
  if (Ask & ~(UINT32)(DARWIN_BOOT_FDT_MEMORY | DARWIN_BOOT_FDT_DEVICES)) { return EFI_COMPROMISED_DATA; }
  Status = gBS->LocateProtocol (&mFdtClientGuid, NULL, (VOID **)&Fdt);
  if (EFI_ERROR (Status)) {
    Print (L"DARWINBOOT: the tree asks for the FDT and the firmware has no FDT client: %r\n", Status);
    return Status;
  }
  if (Ask & DARWIN_BOOT_FDT_MEMORY) {
    Status = FillMemory (Fdt, *Tree, *TreeSize, Chosen);
    if (EFI_ERROR (Status)) { return Status; }
  }
  if (Ask & DARWIN_BOOT_FDT_DEVICES) {
    Status = FillDevices (Fdt, Tree, TreeSize);
    if (EFI_ERROR (Status)) { return Status; }
  }
  return EFI_SUCCESS;
}
