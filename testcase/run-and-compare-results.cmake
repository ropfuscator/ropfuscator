# ${PLAIN_BIN}: plain binary
# ${ROPF_BIN}: ropfuscated binary
set(PLAIN_RESULT _result_${PLAIN_BIN})
set(ROPF_RESULT _result_${ROPF_BIN})
execute_process(COMMAND $<TARGET_FILE:${PLAIN_BIN}> OUTPUT_FILE ${PLAIN_RESULT})
execute_process(COMMAND $<TARGET_FILE:${ROPF_BIN}>  OUTPUT_FILE ${ROPF_RESULT})
execute_process(COMMAND ${CMAKE_COMMAND} -E compare_files ${PLAIN_RESULT} ${ROPF_RESULT})
