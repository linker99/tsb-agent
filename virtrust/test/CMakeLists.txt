# Copyright (c)

find_program(OPENSSL_EXECUTABLE openssl)

if(OPENSSL_EXECUTABLE)
   message(STATUS "Openssl executable found at: {OPENSSL_EXECUTABLE}")
   message(STATUS "Generate test certificates at: ${CMAKE_CURRENT_LIST_DIR}/cert")


   # create ca sk and root cert
   execute_process(
    COMMAND 
      ${OPENSSL_EXECUTABLE} req -x509 -newkey rsa:2048 -nodes -keyout sk.pem
      -out cert.pem -days 365 -subj
      "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com" -nodes
      WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/ca
      OUTPUT_QUIET)

    
    # -----------------
    # server
    # -----------------

    # create server's sk
    execute_process (
        COMMAND ${OPENSSL_EXECUTABLE} genrsa -out sk.pem 2048
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/server
        OUTPUT_QUIET)

   # create csr for server
   execute_process(
    COMMAND 
      ${OPENSSL_EXECUTABLE} req -new -key sk.pem -out csr.pem -subj
      "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com"
      WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/server
      OUTPUT_QUIET)

   # Make CA sign server's csr
   execute_process(
    COMMAND 
      ${OPENSSL_EXECUTABLE} x509 -req -in server.csr -CA ../ca/cert.pem -CAkey
       ../ca/sk.pem -CAcreateserial -out cert.pem -days 365 -sha256
      WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/server
      OUTPUT_QUIET)


    # ------------
    # client
    # -----------

    # create server's sk
    execute_process(
        COMMAND ${OPENSSL_EXECUTABLE} genrsa -out sk.pem 2048
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/client
        OUTPUT_QUIET)

    # create csr for server
    execute_process(
        COMMAND ${OPENSSL_EXECUTABLE} req -new -key sk.pem -out client.csr -subj
        "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com"
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/client
        OUTPUT_QUIET)

    # Make CA sign client's csr
    execute_process(
        COMMAND ${OPENSSL_EXECUTABLE} x509 -req -in client.csr -CA ../ca/cert.pem -CAkey
        ../ca/sk.pem -CAcreateserial -out cert.pem -days 365 -sha256
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/client
        OUTPUT_QUIET)

    message(
        STATUS "Generated test certificates generated at: ${CMAKE_CURRENT_LIST_DIR}/cert")
else ()
    message(WARNING "Openssl executable not found. Test certificates not generated.")
endif()
