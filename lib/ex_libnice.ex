defmodule ExLibnice do
  @moduledoc """
  Module that wraps functions from [libnice](https://libnice.freedesktop.org/libnice/index.html).

  For more information about each function please refer to [libnice] documentation.
  """

  use GenServer
  use Bunch

  require Logger
  require Unifex.CNode

  defmodule State do
    @moduledoc false
    use Bunch.Access

    @type t :: %__MODULE__{
            parent: pid,
            impl: NIF | CNode,
            cnode: Unifex.CNode.t(),
            native_state: reference(),
            stream_components: %{stream_id: integer(), n_components: integer()},
            mdns_queries: %{
              query: String.t(),
              candidate: {sdp :: String.t(), stream_id :: integer(), component_id :: integer()}
            }
          }

    @enforce_keys [:parent, :impl]
    defstruct @enforce_keys ++
                [
                  cnode: nil,
                  native_state: nil,
                  stream_components: %{},
                  mdns_queries: %{}
                ]
  end

  @typedoc """
  Fully qualified domain name e.g. "my.domain.com".
  """
  @type fqdn() :: String.t()

  @type stun_server() :: %{server_addr: :inet.ip_address() | fqdn(), server_port: 0..65_535}

  @typedoc """
  Type describing TURN server configuration
  """
  @type relay_info :: %{
          server_addr: :inet.ip_address() | fqdn(),
          server_port: 0..65_535,
          username: String.t(),
          password: String.t(),
          relay_type: :udp | :tcp | :tls
        }

  @typedoc """
  Type describing ExLibnice configuration.

  It's a keyword list containing the following keys:
  * impl - implementation to use. Possible values are NIF and CNode.
  You can also choose `impl` via config.exs by
  ```elixir
  config :ex_libnice, impl: :NIF
  ```
  * parent - pid of calling process
  * stun_servers - list of stun servers in form of ip:port
  * controlling_mode - refer to RFC 8445 section 4 - Controlling and Controlled Agent
  * min_port..max_port - the port range to use. Pass 0..0 if you not willing to set it.
  Passed port range will be set for each newly added stream. At this moment it is not possible to
  set port range per stream.
  """
  @type opts_t :: [
          impl: NIF | CNode,
          parent: pid(),
          stun_servers: [stun_server()],
          controlling_mode: boolean(),
          port_range: 0..65_535
        ]

  @doc """
  Spawns new process responsible for interacting with `libnice`.
  """
  @spec start_link(opts :: opts_t) :: {:ok, pid()}
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Adds a new stream with `n_components` components. `name` is optional but not passing it will
  influence on SDP string format, see `generate_local_sdp/1`.
  """
  @spec add_stream(pid :: pid(), n_components :: integer(), name :: String.t()) ::
          {:ok, integer()}
          | {:error,
             :failed_to_add_stream | :invalid_stream_or_duplicate_name | :failed_to_attach_recv}
  def add_stream(pid, n_components, name \\ "") do
    GenServer.call(pid, {:add_stream, n_components, name})
  end

  @doc """
  Removes stream with id `stream_id`.
  """
  @spec remove_stream(pid :: pid(), stream_id :: integer()) :: :ok
  def remove_stream(pid, stream_id) do
    GenServer.cast(pid, {:remove_stream, stream_id})
  end

  @doc """
  Sets TURN server. Can be called multiple times for the same component to add many TURN
  servers.
  """
  @spec set_relay_info(
          pid :: pid(),
          stream_id :: integer(),
          component_id :: integer() | [integer()] | :all,
          relay_info :: relay_info() | [relay_info()]
        ) ::
          :ok
          | {:error,
             :bad_stream_id | :bad_relay_type | :failed_to_resolve_addr | :failed_to_set_turn}
  def set_relay_info(pid, stream_id, component_id, relay_info) do
    GenServer.call(pid, {:set_relay_info, stream_id, component_id, relay_info})
  end

  @doc """
  Forget all TURN servers for given component.
  """
  @spec forget_relays(pid :: pid(), stream_id :: integer(), component_id :: integer()) ::
          :ok | {:error, :component_not_found}
  def forget_relays(pid, stream_id, component_id) do
    GenServer.call(pid, {:forget_relays, stream_id, component_id})
  end

  @doc """
  Generates a SDP string containing the local candidates and credentials for all streams and
  components.

  Notice that:
  - local candidates will be present in the result SDP only if `gather_candidates/1` has been
  invoked previously
  - if a stream is created without a name the 'm' line will contain '-' mark but SDP in this form
  will not be parsable by `parse_remote_sdp/2`
  """
  @spec generate_local_sdp(pid :: pid()) :: {:ok, sdp :: String.t()}
  def generate_local_sdp(pid) do
    GenServer.call(pid, :generate_local_sdp)
  end

  @doc """
  Parses a remote SDP string setting credentials and remote candidates for proper streams and
  components.

  It is important that `m` line does not contain `-` mark but the name of the stream.
  """
  @spec parse_remote_sdp(pid :: pid(), sdp :: String.t()) ::
          {:ok, added_cand_num :: integer()} | {:error, :failed_to_parse_sdp}
  def parse_remote_sdp(pid, sdp) do
    GenServer.call(pid, {:parse_remote_sdp, sdp})
  end

  @doc """
  Returns local credentials for stream with id `stream_id`.
  """
  @spec get_local_credentials(pid :: pid(), stream_id :: integer()) ::
          {:ok, credentials :: String.t()} | {:error, :failed_to_get_credentials}
  def get_local_credentials(pid, stream_id) do
    GenServer.call(pid, {:get_local_credentials, stream_id})
  end

  @doc """
  Sets remote credentials for stream with `stream_id`.

  Credentials have to be passed in form of `ufrag pwd`.
  """
  @spec set_remote_credentials(pid :: pid(), credentials :: String.t(), stream_id :: integer()) ::
          :ok | {:error, :failed_to_set_credentials}
  def set_remote_credentials(pid, credentials, stream_id) do
    GenServer.call(pid, {:set_remote_credentials, credentials, stream_id})
  end

  @doc """
  Starts gathering candidates process for stream with id `stream_id`.

  May cause the parent process receive following messages:
  - `{:new_candidate_full, candidate}` - new local candidate
  - `{:candidate_gathering_done, stream_id}` - gathering candidates for stream with `stream_id`
  has been done
  """
  @spec gather_candidates(pid :: pid(), stream_id :: integer()) ::
          :ok | {:error, :invalid_stream_or_allocation}
  def gather_candidates(pid, stream_id) do
    GenServer.call(pid, {:gather_candidates, stream_id})
  end

  @doc """
  Indicates that all remote candidates for stream with id `stream_id` have been passed.

  After receiving this message components can change their state to `FAILED` if all their
  connectivity checks have failed. Not sending this message will cause components stay in
  `CONNECTING` state. (In fact there is a bug and components can change their state to `FAILED`
  even without sending this message. Please refer to
  [#120](https://gitlab.freedesktop.org/libnice/libnice/-/issues/120.)
  """
  @spec peer_candidate_gathering_done(pid :: pid(), stream_id :: integer()) ::
          :ok | {:error, :stream_not_found}
  def peer_candidate_gathering_done(pid, stream_id) do
    GenServer.call(pid, {:peer_candidate_gathering_done, stream_id})
  end

  @doc """
  Sets remote candidate for component with id `component_id` in stream with id `stream_id`.

  Candidate has to be passed as SDP string.
  May cause the parent process receive following messages:
  - `{:new_remote_candidate_full, candidate}` - new remote (prflx) candidate
  - `{:new_selected_pair, stream_id, component_id, lfoundation, rfoundation}` - new selected pair
  - `{:component_state_failed, stream_id, component_id}` - component with id `component_id` in
  stream with id `stream_id` has changed state to FAILED
  - `{:component_state_ready, stream_id, component_id}` - component with id `component_id` in stream
  with id `stream_id` has changed state to READY i.e. it is ready to receive and send data
  """
  @spec set_remote_candidate(
          pid :: pid(),
          candidate :: String.t(),
          stream_id :: integer(),
          component_id :: integer()
        ) :: :ok | {:error, :failed_to_parse_sdp_string | :failed_to_set}
  def set_remote_candidate(pid, candidate, stream_id, component_id) do
    GenServer.call(pid, {:set_remote_candidate, candidate, stream_id, component_id})
  end

  @doc """
  Restarts all streams.
  """
  @spec restart(pid :: pid()) :: :ok | {:error, :failed_to_restart}
  def restart(pid) do
    GenServer.call(pid, :restart)
  end

  @doc """
  Restarts stream with id `stream_id`.
  """
  @spec restart_stream(pid :: pid(), stream_id :: integer()) :: :ok | {:error, :failed_to_restart}
  def restart_stream(pid, stream_id) do
    GenServer.call(pid, {:restart_stream, stream_id})
  end

  @doc """
  Sends payload on component with id `component_id` in stream with id `stream_id`. Payload has to
  be in a binary format.
  """
  @spec send_payload(
          pid :: pid(),
          stream_id :: integer(),
          component_id :: integer(),
          payload :: binary()
        ) :: :ok | {:error, :failed_to_send}
  def send_payload(pid, stream_id, component_id, payload) do
    GenServer.call(pid, {:send_payload, stream_id, component_id, payload})
  end

  @doc """
  Stops and cleans up `ExLibnice` instance.
  """
  @spec stop(pid :: pid(), reason :: term(), timeout :: timeout()) :: :ok
  def stop(pid, reason \\ :normal, timeout \\ :infinity) do
    GenServer.stop(pid, reason, timeout)
  end

  # Server API
  @impl true
  def init(opts) do
    min_port..max_port = opts[:port_range]

    {:ok, stun_servers} = lookup_stun_servers(opts[:stun_servers])

    impl = Application.get_env(:ex_libnice, :impl) || opts[:impl] || CNode
    state = %State{parent: opts[:parent], impl: impl}

    {:ok, state} =
      call(impl, :init, [stun_servers, opts[:controlling_mode], min_port, max_port], state)

    Logger.debug("Initializing mDNS lookup process")
    Mdns.Client.start()
    Logger.debug("Registering for mDNS events")
    Mdns.EventManager.register()

    {:ok, state}
  end

  @impl true
  def handle_call({:add_stream, n_components}, from, state) do
    handle_call({:add_stream, n_components, ""}, from, state)
  end

  @impl true
  def handle_call({:add_stream, n_components, name}, _from, state) do
    case call(state.impl, :add_stream, [n_components, name], state) do
      {{:ok, stream_id}, state} ->
        Logger.debug("New stream_id: #{stream_id}")
        {:reply, {:ok, stream_id}, put_in(state.stream_components[stream_id], n_components)}

      {{:error, cause}, state} ->
        Logger.warn("""
        Couldn't add stream with #{n_components} components and name "#{inspect(name)}": \
        #{inspect(cause)}
        """)

        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call({:set_relay_info, stream_id, component_id, relay_info}, _from, state) do
    {ret, state} =
      Bunch.listify(relay_info)
      |> Bunch.Enum.try_reduce(state, fn single_relay_info, state ->
        do_set_relay_info(state, stream_id, component_id, single_relay_info)
      end)

    {:reply, ret, state}
  end

  @impl true
  def handle_call({:forget_relays, stream_id, component_id}, _from, state) do
    case call(state.impl, :forget_relays, [stream_id, component_id], state) do
      {:ok, state} ->
        {:reply, :ok, state}

      {{:error, cause}, state} ->
        Logger.warn("""
        Couldn't forget TURN servers for component: #{inspect(component_id)} in stream: \
        #{inspect(stream_id)}, reason: #{inspect(cause)}
        """)

        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call(:generate_local_sdp, _from, state) do
    {{:ok, local_sdp}, state} = call(state.impl, :generate_local_sdp, [], state)
    Logger.debug("local sdp: #{inspect(local_sdp)}")
    {:reply, {:ok, local_sdp}, state}
  end

  @impl true
  def handle_call({:parse_remote_sdp, remote_sdp}, _from, state) do
    case call(state.impl, :parse_remote_sdp, [remote_sdp], state) do
      {{:ok, added_cand_num}, state} ->
        Logger.debug("parse_remote_sdp: ok; added #{added_cand_num} candidates")
        {:reply, {:ok, added_cand_num}, state}

      {{:error, cause}, state} ->
        Logger.warn("Couldn't parse remote sdp #{inspect(remote_sdp)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call({:get_local_credentials, stream_id}, _from, state) do
    case call(state.impl, :get_local_credentials, [stream_id], state) do
      {{:ok, credentials}, state} ->
        Logger.debug("local credentials: #{credentials}")
        {:reply, {:ok, credentials}, state}

      {{:error, cause}, state} ->
        Logger.error("get_local_credentials: #{inspect(cause)}")
        {{:error, cause}, state}
    end
  end

  @impl true
  def handle_call(
        {:set_remote_credentials, credentials, stream_id},
        _from,
        state
      ) do
    case call(state.impl, :set_remote_credentials, [credentials, stream_id], state) do
      {:ok, state} ->
        Logger.debug("set_remote_credentials: ok")
        {:reply, :ok, state}

      {{:error, cause}, state} ->
        Logger.error("set_remote_credentials: #{inspect(cause)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call({:gather_candidates, stream_id} = msg, _from, state) do
    case call(state.impl, :gather_candidates, [stream_id], state) do
      {:ok, state} ->
        Logger.debug("#{inspect(msg)}")
        {:reply, :ok, state}

      {{:error, cause}, state} ->
        Logger.error("gather_candidates: #{inspect(msg)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call(
        {:peer_candidate_gathering_done, stream_id},
        _ctx,
        state
      ) do
    case call(state.impl, :peer_candidate_gathering_done, [stream_id], state) do
      {:ok, state} ->
        Logger.debug("peer_candidate_gathering_done: ok")
        {:reply, :ok, state}

      {{:error, cause}, state} ->
        Logger.warn("peer_candidate_gathering_done: #{inspect(cause)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call(
        {:set_remote_candidate, "a=", _stream_id, _component_id},
        _from,
        state
      ) do
    Logger.debug("Empty candidate \"a=\". Should we do something with it?")
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:set_remote_candidate, candidate, stream_id, component_id}, _from, state) do
    candidate_sp = String.split(candidate, " ", parts: 6)

    withl candidate_check: 6 <- length(candidate_sp),
          do: address = Enum.at(candidate_sp, 4),
          mdns_check: true <- String.ends_with?(address, ".local") do
      Logger.debug("Sending query to resolve mDNS address #{inspect(address)}")
      Mdns.Client.query(address)
      state = put_in(state, [:mdns_queries, address], {candidate, stream_id, component_id})
      {:reply, :ok, state}
    else
      candidate_check: _ -> {:reply, {:error, :failed_to_parse_sdp_string}, state}
      mdns_check: _ -> do_set_remote_candidate(candidate, stream_id, component_id, state)
    end
  end

  @impl true
  def handle_call(:restart, _from, state) do
    case call(state.impl, :restart, [], state) do
      {:ok, state} ->
        Logger.debug("ICE restarted")
        {:reply, :ok, state}

      {{:error, cause}, state} ->
        Logger.warn("Couldn't restart ICE")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call({:restart_stream, stream_id}, _from, state) do
    case call(state.impl, :restart_stream, [stream_id], state) do
      {:ok, state} ->
        Logger.debug("Stream #{inspect(stream_id)} restarted")
        {:reply, :ok, state}

      {{:error, cause}, state} ->
        Logger.warn("Couldn't restart stream #{inspect(stream_id)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_call({:send_payload, stream_id, component_id, payload}, _from, state) do
    case call(state.impl, :send_payload, [stream_id, component_id, payload], state) do
      {:ok, state} ->
        {:reply, :ok, state}

      {{:error, cause}, state} ->
        Logger.warn("Couldn't send payload: #{inspect(cause)}")
        {:reply, {:error, cause}, state}
    end
  end

  @impl true
  def handle_cast({:remove_stream, stream_id}, state) do
    {:ok, state} = call(state.impl, :remove_stream, [stream_id], state)
    Logger.debug("remove_stream #{stream_id}: ok")
    {_n_components, state} = pop_in(state.stream_components[stream_id])
    {:noreply, state}
  end

  @impl true
  def handle_info({:new_candidate_full, _cand} = msg, %State{parent: parent} = state) do
    Logger.debug("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info({:new_remote_candidate_full, _cand} = msg, %State{parent: parent} = state) do
    Logger.debug("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info({:candidate_gathering_done, _stream_id} = msg, %State{parent: parent} = state) do
    Logger.debug("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:new_selected_pair, _stream_id, _component_id, _lfoundation, _rfoundation} = msg,
        %State{parent: parent} = state
      ) do
    Logger.debug("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:component_state_ready, _stream_id, _component_id} = msg,
        %State{parent: parent} = state
      ) do
    Logger.debug("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:component_state_failed, _stream_id, _component_id} = msg,
        %State{parent: parent} = state
      ) do
    Logger.warn("#{inspect(msg)}")
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:ice_payload, _stream_id, _component_id, _payload} = msg,
        %State{parent: parent} = state
      ) do
    send(parent, msg)
    {:noreply, state}
  end

  @impl true
  def handle_info({_namespace, %Mdns.Client.Device{} = dev} = msg, state) do
    Logger.debug("mDNS address resolved #{inspect(msg)}")

    {query, state} = pop_in(state, [:mdns_queries, dev.domain])

    case query do
      nil ->
        Logger.debug("""
        mDNS response for non existing candidate.
        We have probably already resolved address #{inspect(dev.domain)}
        """)

      {candidate, stream_id, component_id} ->
        candidate_parts =
          String.split(candidate, " ", parts: 6)
          |> List.replace_at(4, :inet.ntoa(dev.ip))

        candidate = Enum.join(candidate_parts, " ")
        do_set_remote_candidate(candidate, stream_id, component_id, state)
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warn("Unknown message #{inspect(msg)}")
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, %State{native_state: nil, cnode: cnode}) do
    Logger.debug("Terminating ExLibnice instance #{inspect(self())}")
    Unifex.CNode.stop(cnode)
  end

  @impl true
  def terminate(_reason, _state) do
    Logger.debug("Terminating ExLibnice instance #{inspect(self())}")
    :ok
  end

  defp do_set_relay_info(state, stream_id, n_components, relay_info) when is_list(n_components),
    do:
      Bunch.Enum.try_reduce(n_components, state, fn n_component, state ->
        do_set_relay_info(state, stream_id, n_component, relay_info)
      end)

  defp do_set_relay_info(state, stream_id, :all, relay_info) do
    case Map.get(state.stream_components, stream_id) do
      nil ->
        Logger.warn("Couldn't set TURN servers. No stream with id #{inspect(stream_id)}")

        {{:error, :bad_stream_id}, state}

      n_components ->
        Bunch.Enum.try_reduce(1..n_components, state, fn n_component, state ->
          do_set_relay_info(state, stream_id, n_component, relay_info)
        end)
    end
  end

  defp do_set_relay_info(
         state,
         stream_id,
         component_id,
         %{server_addr: server_addr, server_port: server_port, relay_type: relay_type}
       )
       when relay_type not in [:udp, :tcp, :tls] do
    Logger.warn("""
    Couldn't set TURN server #{inspect(server_addr)} #{inspect(server_port)} \
    #{inspect(relay_type)} for component: #{inspect(component_id)} in stream: \
    #{inspect(stream_id)}, cause: bad_relay_type
    """)

    {{:error, :bad_relay_type}, state}
  end

  defp do_set_relay_info(state, stream_id, component_id, %{
         server_addr: server_addr,
         server_port: server_port,
         username: username,
         password: password,
         relay_type: relay_type
       }) do
    with {:ok, server_ip} <- lookup_addr(server_addr),
         {:ok, state} <-
           call(
             state.impl,
             :set_relay_info,
             [
               stream_id,
               component_id,
               :inet.ntoa(server_ip) |> to_string(),
               server_port,
               username,
               password,
               Atom.to_string(relay_type)
             ],
             state
           ) do
      {:ok, state}
    else
      {{:error, cause}, _state} = ret ->
        Logger.warn("""
        Couldn't set TURN server #{inspect(server_addr)} #{inspect(server_port)} \
        #{inspect(relay_type)} for component: #{inspect(component_id)} in stream: \
        #{inspect(stream_id)}, cause: #{inspect(cause)}
        """)

        ret
    end
  end

  defp do_set_remote_candidate(candidate, stream_id, component_id, state) do
    case call(state.impl, :set_remote_candidate, [candidate, stream_id, component_id], state) do
      {:ok, state} ->
        Logger.debug("Set remote candidate: #{inspect(candidate)}")
        {:reply, :ok, state}

      {{:error, cause}, state} ->
        Logger.warn("Couldn't set remote candidate: #{inspect(cause)}")
        {:reply, {:error, cause}, state}
    end
  end

  defp call(NIF, :init = func, args, state) do
    {ret, native_state} = apply(ExLibnice.Native, func, args)
    {ret, %{state | native_state: native_state}}
  end

  defp call(NIF, func, args, state) do
    {ret, native_state} = apply(ExLibnice.Native, func, [state.native_state | args])
    {ret, %{state | native_state: native_state}}
  end

  defp call(CNode, func, args, %{cnode: nil} = state) do
    {:ok, cnode} = Unifex.CNode.start_link(:native)
    call(CNode, func, args, %{state | cnode: cnode})
  end

  defp call(CNode, func, args, state) do
    ret = apply(Unifex.CNode, :call, [state.cnode, func, args])
    {ret, state}
  end

  defp lookup_stun_servers(stun_servers) do
    Bunch.Enum.try_map(stun_servers, fn %{server_addr: addr, server_port: port} ->
      case lookup_addr(addr) do
        {:ok, ip} -> {:ok, "#{:inet.ntoa(ip)}:#{port}"}
        {:error, _cause} = error -> error
      end
    end)
  end

  defp lookup_addr({_a, _b, _c, _d} = addr), do: {:ok, addr}
  defp lookup_addr({_a, _b, _c, _d, _e, _f, _g, _h} = addr), do: {:ok, addr}

  defp lookup_addr(addr) when is_binary(addr) do
    case :inet_res.lookup(to_charlist(addr), :in, :a) do
      [] -> {:error, :failed_to_lookup_address}
      [h | _t] -> {:ok, h}
    end
  end
end
