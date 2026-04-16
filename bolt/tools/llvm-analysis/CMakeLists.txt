set(LLVM_LINK_COMPONENTS
  ${BOLT_TARGETS_TO_BUILD}
  CodeGen
  CodeGenTypes
  Core
  MC
  Object
  Remarks
  Support
  Symbolize
  Target
  )

add_bolt_tool(llvm-analysis
  llvm-analysis.cpp
  Symbolizer.cpp
  DISABLE_LLVM_LINK_LLVM_DYLIB
  )

target_include_directories(llvm-analysis PRIVATE
  /Users/hjiang/workspace/triskel/lib/include
  )

target_link_libraries(llvm-analysis
  PRIVATE
  LLVMBOLTRewrite
  LLVMBOLTUtils
  /Users/hjiang/workspace/triskel/build/lib/libtriskel.a
  /opt/homebrew/lib/libfmt.a
  )

include_directories(${BOLT_SOURCE_DIR}/lib)
