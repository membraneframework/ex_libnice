#include "parser.h"

static int parse_stun_servers(NiceAgent *agent, char **stun_servers, unsigned int length);
static int parse_controlling_mode(NiceAgent *agent, int controlling_mode);

int parse_args(NiceAgent *agent, char **stun_servers, unsigned int stun_servers_length,
               int controlling_mode) {
  int res;
  res = parse_stun_servers(agent, stun_servers, stun_servers_length);
  if(res) {
    return res;
  }

  res = parse_controlling_mode(agent, controlling_mode);
  if(res) {
    return res;
  }
  return 0;
}

static int parse_stun_servers(NiceAgent *agent, char **stun_servers, unsigned int length) {
  for(unsigned int i = 0; i < length; i++) {
    char *addr = strtok(stun_servers[i], ":");
    char *port = strtok(NULL, ":");
    if(!addr || !port) {
      return BAD_STUN_FORMAT;
    }
    g_object_set(agent, "stun-server", addr, NULL);
    g_object_set(agent, "stun-server-port", atoi(port), NULL);
  }
  return 0;
}

static int parse_controlling_mode(NiceAgent *agent, int controlling_mode) {
  if(controlling_mode == 0) {
    g_object_set(agent, "controlling_mode", FALSE, NULL);
  } else if(controlling_mode == 1) {
    g_object_set(agent, "controlling_mode", TRUE, NULL);
  } else {
    return BAD_CTLM_FORMAT;
  }
  return 0;
}

void parse_credentials(char *credentials, char **ufrag, char **pwd) {
  *ufrag = strtok(credentials, " ");
  *pwd = strtok(NULL, " ");
}
