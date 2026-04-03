set(LLVM_LINK_COMPONENTS
  ${BOLT_TARGETS_TO_BUILD}
  MC
  Object
  Support
  )

add_bolt_tool(llvm-match
  llvm-match.cpp
  DISABLE_LLVM_LINK_LLVM_DYLIB
  )

target_link_libraries(llvm-match
  PRIVATE
  LLVMBOLTRewrite
  LLVMBOLTUtils
  )

include_directories(${BOLT_SOURCE_DIR}/lib)
