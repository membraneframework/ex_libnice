module ExLibnice.Native

interface [NIF, CNode]

state_type "State"

spec init(stun_servers :: [string], controlling_mode :: bool, min_port :: unsigned,
          max_port :: unsigned) :: {:ok :: label, state}

spec add_stream(state, n_components :: unsigned, name :: string) ::
       {{:ok :: label, stream_id :: unsigned}, state}
       | {{:error :: label, :failed_to_add_stream :: label}, state}
       | {{:error :: label, :invalid_stream_or_duplicate_name :: label}, state}
       | {{:error :: label, :failed_to_attach_recv :: label}, state}

spec remove_stream(state, stream_id :: unsigned) :: {:ok :: label, state}

spec set_relay_info(state, stream_id :: unsigned, component_id :: unsigned, server_ip :: string,
       server_port :: unsigned, username :: string, password :: string, relay_type :: string) ::
       {:ok :: label, state}
       | {{:error :: label, :bad_relay_type :: label}, state}
       | {{:error :: label, :failed_to_set_turn :: label}, state}

spec forget_relays(state, stream_id :: unsigned, component_id :: unsigned) :: {:ok :: label, state}
       | {{:error :: label, :component_not_found :: label}, state}

spec generate_local_sdp(state) :: {{:ok :: label, local_sdp :: string}, state}

spec parse_remote_sdp(state, remote_sdp :: string) :: {{:ok :: label, added_cand_num :: unsigned}, state}
       | {{:error :: label, :failed_to_parse_sdp :: label}, state}

spec get_local_credentials(state, stream_id :: unsigned) :: {{:ok :: label, credentials :: string}, state}
       | {{:error :: label, :failed_to_get_credentials :: label}, state}

spec set_remote_credentials(state, credentials :: string, stream_id :: unsigned) :: {:ok :: label, state}
       | {{:error :: label, :failed_to_set_credentials :: label}, state}

spec gather_candidates(state, stream_id :: unsigned) :: {:ok :: label, state}
       | {{:error :: label, :invalid_stream_or_allocation :: label}, state}

spec peer_candidate_gathering_done(state, stream_id :: unsigned) :: {:ok :: label, state}
       | {{:error :: label, :stream_not_found :: label}, state}

spec set_remote_candidate(state, candidate :: string, stream_id :: unsigned,
       component_id :: unsigned) :: {:ok :: label, state}
       | {{:error :: label, :failed_to_parse_sdp_string :: label}, state}
       | {{:error :: label, :failed_to_set :: label}, state}

spec restart(state) :: {:ok :: label, state}
       | {{:error :: label, :failed_to_restart :: label}, state}

spec restart_stream(state, stream_id :: unsigned) :: {:ok :: label, state}
       | {{:error :: label, :failed_to_restart :: label}, state}

spec send_payload(state, stream_id :: unsigned, component_id :: unsigned, data :: payload) ::
       {:ok :: label, state}
       | {{:error :: label, :failed_to_send :: label}, state}

sends {:new_candidate_full :: label, candidate :: string}
sends {:new_remote_candidate_full :: label, candidate :: string}
sends {:candidate_gathering_done :: label, stream_id :: unsigned}
sends {:new_selected_pair :: label, stream_id :: unsigned, component_id :: unsigned,
  lfoundation :: string, rfoundation :: string}
sends {:component_state_failed :: label, stream_id :: unsigned, component_id :: unsigned}
sends {:component_state_ready :: label, stream_id :: unsigned, component_id :: unsigned}
sends {:ice_payload :: label, stream_id :: unsigned, component_id :: unsigned, payload :: payload}
