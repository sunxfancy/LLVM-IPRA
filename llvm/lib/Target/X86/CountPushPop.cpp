#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/CodeGen/LazyMachineBlockFrequencyInfo.h"
#include "llvm/InitializePasses.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Option/ArgList.h"
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86InstrBuilder.h"
#include "X86InstrInfo.h"

#include <string>

using namespace llvm;

#define DEBUG_TYPE "count-push-pop"

namespace llvm {
ALWAYS_ENABLED_STATISTIC(PushCount, "dynamic push count");
ALWAYS_ENABLED_STATISTIC(PopCount, "dynamic pop count");

ALWAYS_ENABLED_STATISTIC(StaticPushCount, "static push count");
ALWAYS_ENABLED_STATISTIC(StaticPopCount, "static pop count");

class CountPushPop : public MachineFunctionPass {
public:
    static char ID; 
    CountPushPop() : MachineFunctionPass(ID) {}
    
    bool runOnMachineFunction(MachineFunction &MF) override {
        // printf("run on function %s\n", MF.getName().str().c_str());
        auto PSI = &getAnalysis<ProfileSummaryInfoWrapperPass>().getPSI();
        auto MBFI = (PSI && PSI->hasProfileSummary()) ?
         &getAnalysis<LazyMachineBlockFrequencyInfoPass>().getBFI() :
         nullptr;
        for (auto &MBB : MF) {
            for (auto &MI : MBB) {
                // MI.getFlag(MachineInstr::FrameSetup) && 
                if (MI.getOpcode() == X86::PUSH64r) {
                    if (MBFI) {
                        auto p = MBFI->getBlockProfileCount(&MBB);
                        if (p) PushCount += p.getValue();
                    } 
                    StaticPushCount += 1;
                } else if (MI.getOpcode() == X86::POP64r) {
                    if (MBFI) {
                        auto p = MBFI->getBlockProfileCount(&MBB);
                        if (p) PopCount += p.getValue();
                    } 
                    StaticPopCount += 1;
                }
            }
        }
        
        return false;
    }

    bool doInitialization(Module &M) override {  
        PushCount = 0;
        PopCount = 0;
        StaticPushCount = 0;
        StaticPopCount = 0;
        return false; 
    }

    bool doFinalization(Module &M) override {  
        FILE* pOut = fopen("/tmp/count-push-pop.txt", "a");
        if (pOut) {
            fprintf(pOut, "counting in %s\n", M.getName().str().c_str());
            fprintf(pOut, "dynamic push count: %zu\n", PushCount.getValue());
            fprintf(pOut, "dynamic pop  count: %zu\n", PopCount.getValue());
            fprintf(pOut, "static  push count: %zu\n", StaticPushCount.getValue());
            fprintf(pOut, "static  pop  count: %zu\n", StaticPopCount.getValue());
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
}

char CountPushPop::ID = 0;
static RegisterPass<CountPushPop> X("push-pop-counter", "Count Push/Pop Pass");

MachineFunctionPass* createCountPushPopPass() {
    return new CountPushPop();
}

// INITIALIZE_PASS_BEGIN(CountPushPop, DEBUG_TYPE,
//                       "Count Push and Pop Actions", true, true)
// INITIALIZE_PASS_DEPENDENCY(PEI)
// INITIALIZE_PASS_DEPENDENCY(MachineBlockFrequencyInfo)
// INITIALIZE_PASS_END(CountPushPop, DEBUG_TYPE,
//                     "Count Push and Pop Actions", true, true)

