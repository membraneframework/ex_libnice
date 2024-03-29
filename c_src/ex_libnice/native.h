#pragma once

#include <signal.h>
#include <nice/agent.h>
#include <unifex/unifex.h>

typedef struct State State;

struct State {
  UnifexEnv *env;
  GMainLoop *gloop;
  NiceAgent *agent;
  UnifexTid gloop_tid;
  unsigned int min_port;
  unsigned int max_port;
  UnifexPid reply_to;
};

#include "_generated/native.h"
