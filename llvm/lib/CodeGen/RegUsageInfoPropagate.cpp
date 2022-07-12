//=--- RegUsageInfoPropagate.cpp - Register Usage Informartion Propagation --=//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// This pass is required to take advantage of the interprocedural register
/// allocation infrastructure.
///
/// This pass iterates through MachineInstrs in a given MachineFunction and at
/// each callsite queries RegisterUsageInfo for RegMask (calculated based on
/// actual register allocation) of the callee function, if the RegMask detail
/// is available then this pass will update the RegMask of the call instruction.
/// This updated RegMask will be used by the register allocator while allocating
/// the current MachineFunction.
///
//===----------------------------------------------------------------------===//

#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/RegisterUsageInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

using namespace llvm;

#define DEBUG_TYPE "ip-regalloc"

#define RUIP_NAME "Register Usage Information Propagation"


static cl::opt<std::string>
    IPRAProfile("ipra-profile", cl::init(""), cl::value_desc("filename"), cl::Hidden,
               cl::desc("Profile for FDO based interprocedural register allocation "
                        "to reduce load/store at procedure calls."));

namespace {

class RegUsageInfoPropagation : public MachineFunctionPass {
public:
  RegUsageInfoPropagation() : MachineFunctionPass(ID) {
    PassRegistry &Registry = *PassRegistry::getPassRegistry();
    initializeRegUsageInfoPropagationPass(Registry);
  }

  StringRef getPassName() const override { return RUIP_NAME; }

  bool runOnMachineFunction(MachineFunction &MF) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<PhysicalRegisterUsageInfo>();
    AU.setPreservesAll();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  static char ID;

private:
  static void setRegMask(MachineInstr &MI, ArrayRef<uint32_t> RegMask) {
    assert(RegMask.size() ==
           MachineOperand::getRegMaskSize(MI.getParent()->getParent()
                                          ->getRegInfo().getTargetRegisterInfo()
                                          ->getNumRegs())
           && "expected register mask size");
    for (MachineOperand &MO : MI.operands()) {
      if (MO.isRegMask())
        MO.setRegMask(RegMask.data());
    }
  }
};

} // end of anonymous namespace

INITIALIZE_PASS_BEGIN(RegUsageInfoPropagation, "reg-usage-propagation",
                      RUIP_NAME, false, false)
INITIALIZE_PASS_DEPENDENCY(PhysicalRegisterUsageInfo)
INITIALIZE_PASS_END(RegUsageInfoPropagation, "reg-usage-propagation",
                    RUIP_NAME, false, false)

char RegUsageInfoPropagation::ID = 0;

// Assumes call instructions have a single reference to a function.
static const Function *findCalledFunction(const Module &M,
                                          const MachineInstr &MI) {
  for (const MachineOperand &MO : MI.operands()) {
    if (MO.isGlobal())
      return dyn_cast<const Function>(MO.getGlobal());

    if (MO.isSymbol())
      return M.getFunction(MO.getSymbolName());
  }

  return nullptr;
}

struct IRPAProfile {
  std::set<std::string> HotFunctions;
  std::map<std::string, std::set<unsigned>> HotBasicBlocks;

  void readProfile(const std::string &Filename) {
    std::ifstream File(Filename);
    if (!File.is_open())
      return;
    std::string name; 
    while (std::getline(File, name)) {
      std::string bb_idx_vec;
      std::getline(File, bb_idx_vec);
      std::stringstream ss(bb_idx_vec);
      std::set<unsigned> BBs;

      unsigned BB_index;
      while (ss >> BB_index)
        BBs.insert(BB_index);
      
      HotBasicBlocks[name] = BBs;
      HotFunctions.insert(name);
    }
  }

  bool isHot(StringRef str) {
    return HotFunctions.count(str.str());
  }
  bool isHotBB(std::set<unsigned>& s, unsigned BB_index) {
    return s.count(BB_index);
  }
};


bool RegUsageInfoPropagation::runOnMachineFunction(MachineFunction &MF) {
  const Module &M = *MF.getFunction().getParent();
  PhysicalRegisterUsageInfo *PRUI = &getAnalysis<PhysicalRegisterUsageInfo>();
  
  // IRPAProfile Profile;
  // bool enable_profile = false;
  // if (IPRAProfile != "") {
  //   std::cout << "Load IPRAProf: "  << IPRAProfile << std::endl;
  //   Profile.readProfile(IPRAProfile);
  //   if (Profile.isHot(MF.getName())) enable_profile = true;
  // }

  LLVM_DEBUG(dbgs() << " ++++++++++++++++++++ " << getPassName()
                    << " ++++++++++++++++++++  \n");
  LLVM_DEBUG(dbgs() << "MachineFunction : " << MF.getName() << "\n");

  const MachineFrameInfo &MFI = MF.getFrameInfo();
  if (!MFI.hasCalls() && !MFI.hasTailCall())
    return false;

  bool Changed = false;
  // std::set<unsigned>* s;
  // if (enable_profile) 
  //   s = &Profile.HotBasicBlocks[MF.getName().str()];
  for (MachineBasicBlock &MBB : MF) {
    // bool enable_BB_profile = false;
    // if (enable_profile && Profile.isHotBB(*s, MBB.getNumber())) enable_BB_profile = true;
    for (MachineInstr &MI : MBB) {
      if (!MI.isCall())
        continue;
      // if (enable_profile && !enable_BB_profile) continue;
      LLVM_DEBUG(
          dbgs()
          << "Call Instruction Before Register Usage Info Propagation : \n"
          << MI << "\n");

      auto UpdateRegMask = [&](const Function &F) {
        const ArrayRef<uint32_t> RegMask = PRUI->getRegUsageInfo(F);
        if (RegMask.empty())
          return;
        setRegMask(MI, RegMask);
        Changed = true;
      };

      if (const Function *F = findCalledFunction(M, MI)) {
        if (F->isDefinitionExact()) {
          UpdateRegMask(*F);
        } else {
          LLVM_DEBUG(dbgs() << "Function definition is not exact\n");
        }
      } else {
        LLVM_DEBUG(dbgs() << "Failed to find call target function\n");
      }

      LLVM_DEBUG(
          dbgs()
          << "Call Instruction After Register Usage Info Propagation : \n"
          << MI << '\n');
    }
  }

  LLVM_DEBUG(
      dbgs() << " +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                "++++++ \n");
  return Changed;
}

FunctionPass *llvm::createRegUsageInfoPropPass() {
  return new RegUsageInfoPropagation();
}
