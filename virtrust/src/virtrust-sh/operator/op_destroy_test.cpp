/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "gtest/gtest.h"

#include "virtrust-sh/operator/op_destroy.h"

namespace virtrust {

TEST(OpDestroyTest, ParseArgvValidDomainTest) {
  OpDestroy opDestroy;

  // Test with valid domain name argument
  const char *argv[] = {"op_destroy", "test_domain"};
  int argc = 2;

  OpRc result = opDestroy.ParseArgv(argc, const_cast<char **>(argv));

  // Verify ParseArgv returns OK for valid arguments
  EXPECT_EQ(result, OpRc::OK);
}

TEST(OpDestroyTest, ParseArgvHelpFlagTest) {
  OpDestroy opDestroy;

  // Test with help Flag
  const char *argv[] = {"op_destroy", "--help"};
  int argc = 2;

  OpRc result = opDestroy.ParseArgv(argc, const_cast<char **>(argv));

  // Verify ParseArgv returns OK for help flag (should not execute)
  EXPECT_EQ(result, OpRc::OK);
}

TEST(OpDestroyTest, ParseArgvHelpShortFlagTest) {
  OpDestroy opDestroy;

  // Test with short help flag
  const char *argv[] = {"op_destroy", "-h"};
  int argc = 2;

  OpRc result = opDestroy.ParseArgv(argc, const_cast<char **>(argv));

  // Verify ParseArgv returns OK for short help flag (should not execute)
  EXPECT_EQ(result, OpRc::OK);
}

TEST(OpDestroyTest, ParseArgvMissingDomainTest) {
  OpDestroy opDestroy;

  // Test with no domain name argument
  const char *argv[] = {"op_destroy"};
  int argc = 1;

  OpRc result = opDestroy.ParseArgv(argc, const_cast<char **>(argv));

  // Verify ParseArgv returns ERROR for missing domain
  EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpDestroyTest, ParseArgvExtraArgumentsTest) {
  OpDestroy opDestroy;

  // Test with extra arguments
  const char *argv[] = {"op_destroy", "domain1", "domain2"};
  int argc = 3;

  OpRc result = opDestroy.ParseArgv(argc, const_cast<char **>(argv));

  // Verify ParseArgv handles ERROR for too many arguments
  EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpDestroyTest, ParseArgvInvalidOptionTest) {
  OpDestroy opDestroy;

  // Test with invalid option
  const char *argv[] = {"op_destroy", "--invalid-option"};
  int argc = 2;

  OpRc result = opDestroy.ParseArgv(argc, const_cast<char **>(argv));

  // Verify ParseArgv handles ERROR for invalid option
  EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpDestroyTest, ParseArgvDomainNameStrorageTest) {
  OpDestroy opDestroy;

  // Test that domain name is properly stored
  const char *argv[] = {"op_destroy", "test-domain-123"};
  int argc = 2;

  OpRc result = opDestroy.ParseArgv(argc, const_cast<char **>(argv));

  // Verify ParseArgv returns OK and domain name is stored
  EXPECT_EQ(result, OpRc::OK);
  // Note: Cannot directly access private member domainName_ for verification
  // but we can verify the function doesn't crash and handles correctly
}
} // namespace virtrust
