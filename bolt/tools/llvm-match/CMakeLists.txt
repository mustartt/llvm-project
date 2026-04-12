set(LLVM_LINK_COMPONENTS
  ${BOLT_TARGETS_TO_BUILD}
  CodeGen
  CodeGenTypes
  Core
  MC
  Object
  Support
  Target
  )

add_bolt_tool(llvm-match
  llvm-match.cpp
  DISABLE_LLVM_LINK_LLVM_DYLIB
  )

target_include_directories(llvm-match PRIVATE
  /Users/hjiang/workspace/triskel/lib/include
  )

target_link_libraries(llvm-match
  PRIVATE
  LLVMBOLTRewrite
  LLVMBOLTUtils
  /Users/hjiang/workspace/triskel/build/lib/libtriskel.a
  /opt/homebrew/lib/libfmt.a
  )

include_directories(${BOLT_SOURCE_DIR}/lib)
