defmodule ExLibniceTest do
  use ExUnit.Case, async: true

  setup do
    {:ok, pid} =
      ExLibnice.start_link(
        parent: self(),
        stun_servers: ["64.233.161.127:19302"],
        controlling_mode: true,
        port_range: 0..0
      )

    [pid: pid]
  end

  test "add stream", context do
    pid = context[:pid]

    {:ok, stream_id} = ExLibnice.add_stream(pid, 1)
    assert stream_id > 0

    {:ok, stream_id} = ExLibnice.add_stream(pid, 1, "")
    assert stream_id > 0

    {:ok, stream_id} = ExLibnice.add_stream(pid, 1, "audio")
    assert stream_id > 0

    {:error, :invalid_stream_or_duplicate_name} = ExLibnice.add_stream(pid, 1, "audio")
  end

  test "add turn server", context do
    pid = context[:pid]
    {:ok, stream_id} = ExLibnice.add_stream(pid, 3, "audio")

    assert :ok ==
             ExLibnice.set_relay_info(
               pid,
               stream_id,
               1,
               {"127.0.0.1", 3478, "username", "password", :udp}
             )

    assert :ok ==
             ExLibnice.set_relay_info(
               pid,
               stream_id,
               [2, 3],
               {"127.0.0.1", 3478, "username", "password", :udp}
             )

    assert :ok ==
             ExLibnice.set_relay_info(
               pid,
               stream_id,
               :all,
               {"127.0.0.2", 3478, "username", "password", :udp}
             )

    assert {:error, :bad_stream_id} ==
             ExLibnice.set_relay_info(
               pid,
               2,
               :all,
               {"127.0.0.1", 3478, "username", "password", :udp}
             )

    assert {:error, :bad_relay_type} ==
             ExLibnice.set_relay_info(
               pid,
               stream_id,
               1,
               {"127.0.0.1", 3478, "username", "password", :bad_relay_type}
             )

    assert {:error, :failed_to_set_turn} ==
             ExLibnice.set_relay_info(
               pid,
               stream_id,
               1,
               {"abc.com", 3478, "username", "password", :udp}
             )

    assert {:error, :failed_to_set_turn} ==
             ExLibnice.set_relay_info(
               pid,
               stream_id,
               [3, 5],
               {"127.0.0.1", 3478, "username", "password", :udp}
             )
  end

  test "remove turn server", context do
    pid = context[:pid]
    {:ok, stream_id} = ExLibnice.add_stream(pid, 1, "audio")

    assert :ok ==
             ExLibnice.set_relay_info(
               pid,
               stream_id,
               1,
               {"127.0.0.1", 3478, "username", "password", :udp}
             )

    assert :ok == ExLibnice.forget_relays(pid, stream_id, 1)
    assert {:error, :component_not_found} == ExLibnice.forget_relays(pid, stream_id, 10)
  end

  test "generate_local_sdp", context do
    pid = context[:pid]
    {:ok, _stream_id} = ExLibnice.add_stream(pid, 1, "audio")
    {:ok, sdp} = ExLibnice.generate_local_sdp(pid)
    assert String.contains?(sdp, ["v=0", "m=audio", "a=ice-ufrag", "a=ice-pwd"])
  end

  test "parse_remote_sdp", context do
    pid = context[:pid]

    {:ok, _stream_id} = ExLibnice.add_stream(pid, 1, "audio")

    {:ok, 0} =
      ExLibnice.parse_remote_sdp(
        pid,
        "v=0\r\nm=audio 0 ICE/SDP\nc=IN IP4 0.0.0.0\na=ice-ufrag:8Fp+\na=ice-pwd:BVsIrRqHCcr/lr7JPgHa8k\n"
      )

    {:error, :failed_to_parse_sdp} =
      ExLibnice.parse_remote_sdp(
        pid,
        "v=0\r\nm=audio 0 ICE/SDP\nc=IN IP4 0.0.0.0\na=ice-ufrag:8Fp+\na=ice-pwd:BVsIrRqHCcr/lr7JPgHa8k\nm=audio 0 ICE/SDP\nc=IN IP4 0.0.0.0\na=ice-ufrag:8Fp+\na=ice-pwd:BVsIrRqHCcr/lr7JPgHa8k\n"
      )
  end

  test "get local credentials", context do
    pid = context[:pid]
    {:ok, stream_id} = ExLibnice.add_stream(pid, 1)
    :ok = ExLibnice.gather_candidates(pid, stream_id)
    {:ok, _credentials} = ExLibnice.get_local_credentials(pid, stream_id)
  end

  test "set remote credentials", context do
    pid = context[:pid]
    {:ok, stream_id} = ExLibnice.add_stream(pid, 1)
    :ok = ExLibnice.set_remote_credentials(pid, "DWIS nuNjkHVrkUZsfLJisHGWHy", 1)

    {:error, :failed_to_set_credentials} =
      ExLibnice.set_remote_credentials(pid, "invalid_cred", stream_id)
  end

  test "gather candidates", context do
    pid = context[:pid]
    {:ok, stream_id} = ExLibnice.add_stream(pid, 1)
    :ok = ExLibnice.gather_candidates(pid, stream_id)
    assert_receive {:new_candidate_full, _candidate}
    assert_receive({:candidate_gathering_done, ^stream_id}, 5000)
    {:error, :invalid_stream_or_allocation} = ExLibnice.gather_candidates(pid, 2000)
  end

  test "peer candidate gathering done", context do
    pid = context[:pid]
    {:ok, stream_id} = ExLibnice.add_stream(pid, 1)
    :ok = ExLibnice.peer_candidate_gathering_done(pid, stream_id)
    {:error, :stream_not_found} = ExLibnice.peer_candidate_gathering_done(pid, 2000)
  end

  test "set remote candidate", context do
    pid = context[:pid]
    {:ok, stream_id} = ExLibnice.add_stream(pid, 1)

    :ok =
      ExLibnice.set_remote_candidate(
        pid,
        "a=candidate:1 1 UDP 2015363327 192.168.83.205 38292 typ host",
        stream_id,
        1
      )

    {:error, :failed_to_parse_sdp_string} =
      ExLibnice.set_remote_candidate(pid, "invalid_sdp_string", stream_id, 1)
  end
end
