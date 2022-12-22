#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86InstrBuilder.h"
#include "X86InstrInfo.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/CodeGen/LazyMachineBlockFrequencyInfo.h"
#include "llvm/InitializePasses.h"
#include "llvm/Option/ArgList.h"
#include "llvm/Support/CommandLine.h"

#include <string>
#include <fstream>

#define DEBUG_TYPE "count-push-pop"

llvm::cl::opt<std::string>
    EnableCPPP("count-push-pop", llvm::cl::Hidden, llvm::cl::init("off"),
      llvm::cl::ValueOptional, llvm::cl::desc("Enable counting push and pop"));


// This is a txt file that contains the function name, then a pair of basic block id - count
llvm::cl::opt<std::string>
  UsePerfdata("use-perfdata", llvm::cl::Hidden, llvm::cl::init(""),
           llvm::cl::ValueOptional, llvm::cl::desc("Enable perfdata push pop counting"));


namespace llvm {

static std::mutex g_file_mutex;

struct Counts {
  uint64_t Push = 0;
  uint64_t Pop = 0;
  uint64_t StaticPush = 0;
  uint64_t StaticPop = 0;
};

class CountPushPop : public MachineFunctionPass {
public:
  static char ID;
  CountPushPop() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override {
    // printf("run on function %s\n", MF.getName().str().c_str());
    auto PSI = &getAnalysis<ProfileSummaryInfoWrapperPass>().getPSI();
    auto MBFI = (PSI && PSI->hasProfileSummary())
                    ? &getAnalysis<LazyMachineBlockFrequencyInfoPass>().getBFI()
                    : nullptr;
    for (auto &MBB : MF) {
      auto p = MBFI->getBlockProfileCount(&MBB);
      for (auto &MI : MBB) {
        if (MI.getOpcode() == X86::PUSH64r) {
          if (MBFI && p) pgo.Push += p.value();
          pgo.StaticPush += 1;
        } else if (MI.getOpcode() == X86::POP64r) {
          if (MBFI && p) pgo.Pop += p.value();
          pgo.StaticPop += 1;
        }
      }
    }

    if (UsePerfdata != "") {
      if (PerfData.count(MF.getName().str())) {
        auto& m = PerfData[MF.getName().str()];
        for (auto &MBB : MF) {
          auto p  = m.find(MBB.getNumber());
          if (p != m.end())
            for (auto &MI : MBB) {
              if (MI.getOpcode() == X86::PUSH64r) {
                    perf.Push += p->second;
              } else if (MI.getOpcode() == X86::POP64r) {
                    perf.Pop += p->second;
              }
            }
        }
      }
    }

    return false;
  }

  Counts pgo, perf;

  std::map<std::string, std::map<uint64_t, uint64_t>> PerfData;

  bool doInitialization(Module &M) override {

    if (UsePerfdata != "") {
      std::ifstream infile(UsePerfdata);
      uint64_t count;
      infile >> count;
      for (uint64_t i = 0; i < count; i++) {
        std::string func_name;
        infile >> func_name;
        uint64_t bb_count;
        infile >> bb_count;
        PerfData[func_name] = std::map<uint64_t, uint64_t>();
        for (uint64_t j = 0; j < bb_count; j++) {
          uint64_t bb_id;
          uint64_t bb_count;
          infile >> bb_id;
          infile >> bb_count;
          PerfData[func_name][bb_id] = bb_count;
        }
      }
    }

    return false;
  }

  bool doFinalization(Module &M) override {
    std::lock_guard<std::mutex> guard(g_file_mutex);
    std::string path = EnableCPPP;
    if (path.empty())
      path = "/tmp/count-push-pop.txt";
    FILE *pOut = fopen(path.c_str(), "a");
    if (pOut) {
      fprintf(pOut, "Using PGO profile counting in %s\n", M.getName().str().c_str());
      fprintf(pOut, "dynamic push count: %zu\n", pgo.Push);
      fprintf(pOut, "dynamic pop  count: %zu\n", pgo.Pop);
      fprintf(pOut, "static  push count: %zu\n", pgo.StaticPush);
      fprintf(pOut, "static  pop  count: %zu\n", pgo.StaticPop);
      if (UsePerfdata != "") {
        fprintf(pOut, "Using perfdata counting in perfdata %s\n", UsePerfdata); 
        fprintf(pOut, "perf push count: %zu\n", perf.Push);
        fprintf(pOut, "perf pop  count: %zu\n", perf.Pop);
      }
      fclose(pOut);
    }
    return false;
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<ProfileSummaryInfoWrapperPass>();
    AU.addRequired<LazyMachineBlockFrequencyInfoPass>();
    AU.setPreservesAll();
    MachineFunctionPass::getAnalysisUsage(AU);
  }
};
} // namespace llvm

char llvm::CountPushPop::ID = 0;
static llvm::RegisterPass<llvm::CountPushPop> X("push-pop-counter",
                                                "Count Push/Pop Pass");

llvm::MachineFunctionPass *createCountPushPopPass() {
  return new llvm::CountPushPop();
}

// INITIALIZE_PASS_BEGIN(CountPushPop, DEBUG_TYPE,
//                       "Count Push and Pop Actions", true, true)
// INITIALIZE_PASS_DEPENDENCY(PEI)
// INITIALIZE_PASS_DEPENDENCY(MachineBlockFrequencyInfo)
// INITIALIZE_PASS_END(CountPushPop, DEBUG_TYPE,
//                     "Count Push and Pop Actions", true, true)
