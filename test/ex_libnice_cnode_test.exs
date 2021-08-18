defmodule ExLibnice.CNode.Test do
  use ExUnit.Case, async: true

  alias ExLibnice.Support.Common

  setup do
    Common.setup(CNode)
  end

  test "add_stream", context do
    Common.test_add_stream(context)
  end

  test "add_turn_server", context do
    Common.test_add_turn_server(context)
  end

  test "remove_turn_server", context do
    Common.test_remove_turn_server(context)
  end

  test "generate_local_sdp", context do
    Common.test_generate_local_sdp(context)
  end

  test "parse_remote_sdp", context do
    Common.test_parse_remote_sdp(context)
  end

  test "get_local_credentials", context do
    Common.test_get_local_credentials(context)
  end

  test "set_remote_credentials", context do
    Common.test_set_remote_credentials(context)
  end

  test "gather_candidates", context do
    Common.test_gather_candidates(context)
  end

  test "peer_candidate_gathering_done", context do
    Common.test_peer_candidate_gathering_done(context)
  end

  test "set_remote_candidate", context do
    Common.test_set_remote_candidate(context)
  end

  test "terminate", context do
    Common.test_terminate(context)
  end
end
