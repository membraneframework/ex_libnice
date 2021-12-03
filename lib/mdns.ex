defmodule ExLibnice.Mdns do
  @moduledoc """
  Module for executing mDNS queries.

  It can be turned off by `config :ex_libnice, mdns: false`.
  """
  use GenServer
  require Logger

  @spec start_link(any()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec query(pid(), String.t()) :: :ok
  def query(from, address) do
    GenServer.cast(__MODULE__, {:query, from, address})
  end

  @impl true
  def init(_opts) do
    Logger.debug("Initializing mDNS lookup process")
    :ok = Mdns.Client.start()
    Logger.debug("Registering for mDNS events")
    Mdns.EventManager.register()
    {:ok, %{queries: %{}}}
  end

  @impl true
  def handle_cast({:query, from, address}, state) do
    Logger.debug("Sending query to resolve mDNS address #{inspect(address)}")
    Mdns.Client.query(address)
    state = put_in(state, [:queries, address], from)
    {:noreply, state}
  end

  @impl true
  def handle_info({_namespace, %Mdns.Client.Device{} = dev} = msg, state) do
    Logger.debug("mDNS address resolved #{inspect(msg)}")

    {from, state} = pop_in(state, [:queries, dev.domain])

    if from do
      send(from, {:mdns_response, dev.domain, dev.ip})
    else
      Logger.debug("""
      mDNS response for non existing query.
      We have probably already resolved address #{inspect(dev.domain)}
      """)
    end

    {:noreply, state}
  end
end
