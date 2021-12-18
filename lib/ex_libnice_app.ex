defmodule ExLibnice.App do
  @moduledoc """
  ExLibnice Application

  It will spawn one mDNS client responsible for executing mDNS queries.
  This feature can be turned off if mDNS is not needed by

  ```elixir
  config :ex_libnice, mdns: false
  ```
  """
  use Application

  require Logger

  @impl true
  def start(_start_type, _start_args) do
    children =
      if Application.get_env(:ex_libnice, :mdns, true) do
        [ExLibnice.Mdns]
      else
        []
      end

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
