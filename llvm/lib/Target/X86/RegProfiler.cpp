#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86InstrBuilder.h"
#include "X86InstrInfo.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/CodeGen/LazyMachineBlockFrequencyInfo.h"
#include "llvm/InitializePasses.h"
#include "llvm/Option/ArgList.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/IR/GlobalValue.h"
#include <string>
#include <fstream>

#define DEBUG_TYPE "reg-profiler"

llvm::cl::opt<bool>
  EnablePPP("EnablePushPopProfile", llvm::cl::Hidden, llvm::cl::init(false),
            llvm::cl::ValueOptional, llvm::cl::desc("Enable counting push and pop"));

llvm::cl::opt<bool>
  EnableSBP("EnableSpillBytesProfile", llvm::cl::Hidden, llvm::cl::init(false),
            llvm::cl::ValueOptional, llvm::cl::desc("Enable counting spill bytes"));

namespace llvm {

struct PPCounts {
  uint64_t Push = 0;
  uint64_t Pop = 0;
  uint64_t StaticPush = 0;
  uint64_t StaticPop = 0;
};

struct SBCounts {
  uint64_t Spill = 0;
  uint64_t Reload = 0;
  uint64_t StaticSpill = 0;
  uint64_t StaticReload = 0;
};

static std::vector<MachineInstr*> getCallsites(MachineBasicBlock &MBB) {
  std::vector<MachineInstr*> res;
  for (auto &MI : MBB) 
    if (MI.isCall()) res.push_back(&MI);
  return res;
}

static bool IsPrologue(MachineBasicBlock &MBB) {
  return &MBB == &MBB.getParent()->front();
}

class InstrumentRegProfilerPass : public MachineFunctionPass {
public:
  static char ID;
  llvm::GlobalValue *SpillReg, *Spill, *Reload, *Push, *Pop;

  llvm::GlobalValue *SpillInCallSite, *ReloadInCallSite;
  llvm::GlobalValue *SpillInCallSiteForNCeSR, *ReloadInCallSiteForNCeSR;
  llvm::GlobalValue *SpillInCallSiteForNCrSR, *ReloadInCallSiteForNCrSR;

  llvm::GlobalValue *SpillInPrologue, *ReloadInPrologue;
  llvm::GlobalValue *SpillInPrologueForNCeSR, *ReloadInPrologueForNCeSR;
  llvm::GlobalValue *SpillInPrologueForNCrSR, *ReloadInPrologueForNCrSR;


  InstrumentRegProfilerPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override {
    LLVM_DEBUG(dbgs() << "Reg profiler run on function " << MF.getName() << "\n");
    LLVM_DEBUG(MF.getFunction().print(dbgs()));
    LLVM_DEBUG(MF.print(dbgs()));
    const auto &TII = *MF.getSubtarget().getInstrInfo();
    llvm::GlobalValue* vars[4] = {Push, Pop, Spill, Reload};
    const unsigned push = 0, pop = 1, spill = 2, reload = 3;

    llvm::GlobalValue* cvars[12] = {
        SpillInCallSite, ReloadInCallSite, SpillInCallSiteForNCeSR, ReloadInCallSiteForNCeSR, SpillInCallSiteForNCrSR, ReloadInCallSiteForNCrSR,
        SpillInPrologue, ReloadInPrologue, SpillInPrologueForNCeSR, ReloadInPrologueForNCeSR, SpillInPrologueForNCrSR, ReloadInPrologueForNCrSR};
    const unsigned sic = 0, ric = 1, sicNCeSR = 2, ricNCeSR = 3, sicNCrSR = 4, ricNCrSR = 5;
    const unsigned sip = 6, rip = 7, sipNCeSR = 8, ripNCeSR = 9, sipNCrSR = 10, ripNCrSR = 11;

    for (auto &MBB : MF) {
      unsigned count[4] = {0, 0, 0, 0};
      for (auto &MI : MBB) {
        if (EnablePPP) {
          if (MI.getOpcode() == X86::PUSH64r) {
            count[push]++;
          } else if (MI.getOpcode() == X86::POP64r) {
            count[pop]++;
          } 
        } 
        if (EnableSBP) {
          Optional<unsigned> Size;
          if (Size = MI.getSpillSize(&TII)) {
            LLVM_DEBUG(dbgs() << "SpillInst: ";  MI.print(dbgs()));
            count[spill] += Size.value();
          } else if (Size = MI.getRestoreSize(&TII)) {
            LLVM_DEBUG(dbgs() << "ReloadInst: ";  MI.print(dbgs()));
            count[reload] += Size.value();
          }
        }
      }
      if (count[push] == 0 && count[pop] == 0 && count[spill] == 0 && count[reload] == 0) continue;
      

      unsigned ccount[12] = {0,0,0,0,0,0,0,0,0,0,0,0};
      auto callsites = getCallsites(MBB);
      if (callsites.size() > 0) {
        bool hasNCeSR = false, hasNCrSR = false;
        for (auto* MI : callsites) {
          auto op = MI->getOperand(0);
          if (!op.isGlobal() || !isa<Function>(op.getGlobal())) continue;
          auto* callee = dyn_cast<Function>(op.getGlobal());
          if (callee->hasFnAttribute("no_caller_saved_registers")) hasNCrSR = true;
          if (callee->hasFnAttribute("no_callee_saved_registers")) hasNCeSR = true;
        }
        if (hasNCeSR) {
          ccount[sicNCeSR] = count[spill];
          ccount[ricNCeSR] = count[reload];
        }
        if (hasNCrSR) {
          ccount[sicNCrSR] = count[spill];
          ccount[ricNCrSR] = count[reload];
        }
        ccount[sic] = count[spill];
        ccount[ric] = count[reload];
      }


      if (IsPrologue(MBB)) {
        Function& F = MF.getFunction();        
        if (F.hasFnAttribute("no_caller_saved_registers")) {
          ccount[sipNCrSR] = count[spill];
          ccount[ripNCrSR] = count[reload];
        }
        if (F.hasFnAttribute("no_callee_saved_registers")) {
          ccount[sipNCeSR] = count[spill];
          ccount[ripNCeSR] = count[reload];
        }
        ccount[sip] = count[spill];
        ccount[rip] = count[reload];
      }

      auto dbgLoc = MBB.begin()->getDebugLoc();
      auto it = MBB.begin();

      // spill rax
      MBB.insert(it, BuildMI(MF, dbgLoc, TII.get(X86::MOV64mr))
        .addReg(0).addImm(1).addReg(0).addGlobalAddress(SpillReg, 0, X86II::MO_TPOFF).addReg(X86::FS).addReg(X86::RAX));

      // here add the profiling code for profiling
      for (int i = 0; i < 4; ++i) {
        if (count[i] == 0) continue;

        MBB.insert(it, BuildMI(MF, dbgLoc, TII.get(X86::MOV64rm), X86::RAX)
          .addReg(0).addImm(1).addReg(0).addGlobalAddress(vars[i], 0, X86II::MO_TPOFF).addReg(X86::FS));
        MBB.insert(it, BuildMI(MF, dbgLoc, TII.get(X86::LEA64r), X86::RAX)
          .addReg(/*Base*/ X86::RAX).addImm(/*Scale*/ 1).addReg(/*Index*/ 0).addImm(/*Disp*/ count[i]).addReg(/*Segment*/ 0));
        MBB.insert(it, BuildMI(MF, dbgLoc, TII.get(X86::MOV64mr))
          .addReg(0).addImm(1).addReg(0).addGlobalAddress(vars[i], 0, X86II::MO_TPOFF).addReg(X86::FS).addReg(X86::RAX));
      }

      for (int i = 0; i < 12; ++i) {
        if (ccount[i] == 0) continue;

        MBB.insert(it, BuildMI(MF, dbgLoc, TII.get(X86::MOV64rm), X86::RAX)
          .addReg(0).addImm(1).addReg(0).addGlobalAddress(cvars[i], 0, X86II::MO_TPOFF).addReg(X86::FS));
        MBB.insert(it, BuildMI(MF, dbgLoc, TII.get(X86::LEA64r), X86::RAX)
          .addReg(/*Base*/ X86::RAX).addImm(/*Scale*/ 1).addReg(/*Index*/ 0).addImm(/*Disp*/ ccount[i]).addReg(/*Segment*/ 0));
        MBB.insert(it, BuildMI(MF, dbgLoc, TII.get(X86::MOV64mr))
          .addReg(0).addImm(1).addReg(0).addGlobalAddress(cvars[i], 0, X86II::MO_TPOFF).addReg(X86::FS).addReg(X86::RAX));
      }

      // reload rax
      MBB.insert(it, BuildMI(MF, dbgLoc, TII.get(X86::MOV64rm), X86::RAX)
        .addReg(0).addImm(1).addReg(0).addGlobalAddress(SpillReg, 0, X86II::MO_TPOFF).addReg(X86::FS));
    }
    LLVM_DEBUG(MF.print(dbgs()));
    return true;
  }

  bool doInitialization(Module &M) override {
    SpillReg = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_SpillReg", Type::getInt64Ty(M.getContext())));
    Spill = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_Spill", Type::getInt64Ty(M.getContext())));
    Reload = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_Reload", Type::getInt64Ty(M.getContext())));
    Push = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_Push", Type::getInt64Ty(M.getContext())));
    Pop = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_Pop", Type::getInt64Ty(M.getContext())));

    SpillInCallSite = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_SpillInCallSite", Type::getInt64Ty(M.getContext())));
    ReloadInCallSite = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_ReloadInCallSite", Type::getInt64Ty(M.getContext())));
    SpillInCallSiteForNCeSR = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_SpillInCallSiteForNCeSR", Type::getInt64Ty(M.getContext())));
    ReloadInCallSiteForNCeSR = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_ReloadInCallSiteForNCeSR", Type::getInt64Ty(M.getContext())));
    SpillInCallSiteForNCrSR = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_SpillInCallSiteForNCrSR", Type::getInt64Ty(M.getContext())));
    ReloadInCallSiteForNCrSR = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_ReloadInCallSiteForNCrSR", Type::getInt64Ty(M.getContext())));
    SpillInPrologue = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_SpillInPrologue", Type::getInt64Ty(M.getContext())));
    ReloadInPrologue = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_ReloadInPrologue", Type::getInt64Ty(M.getContext())));
    SpillInPrologueForNCeSR = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_SpillInPrologueForNCeSR", Type::getInt64Ty(M.getContext())));
    ReloadInPrologueForNCeSR = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_ReloadInPrologueForNCeSR", Type::getInt64Ty(M.getContext())));
    SpillInPrologueForNCrSR = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_SpillInPrologueForNCrSR", Type::getInt64Ty(M.getContext())));
    ReloadInPrologueForNCrSR = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_ReloadInPrologueForNCrSR", Type::getInt64Ty(M.getContext())));
    return true;
  }

  // bool doInitialization(Module &M) override {
  //   auto Ty = Type::getInt64Ty(M.getContext());
  //   auto createGlobal = [&M, Ty](StringRef name) {
  //     return dyn_cast<GlobalValue>(M.getOrInsertGlobal(name, Ty, [=] {
  //       return new GlobalVariable(Ty, false, GlobalVariable::ExternalLinkage,
  //                               nullptr, name, GlobalValue::ThreadLocalMode::GeneralDynamicTLSModel);
  //     }));
  //   };
  //   Spill = createGlobal("__LLVM_IRPP_Spill");
  //   Reload = createGlobal("__LLVM_IRPP_Reload");
  //   Push = createGlobal("__LLVM_IRPP_Push");
  //   Pop = createGlobal("__LLVM_IRPP_Pop");
  //   return true;
  // }

  bool doFinalization(Module &M) override {
    return false;
  }
};
} // namespace llvm

char llvm::InstrumentRegProfilerPass::ID = 0;
static llvm::RegisterPass<llvm::InstrumentRegProfilerPass> X("instrument-reg-profiler",
                                                "Instrument reg profiler pass");

llvm::MachineFunctionPass *createInstrumentRegProfilerPassPass() {
  return new llvm::InstrumentRegProfilerPass();
}
