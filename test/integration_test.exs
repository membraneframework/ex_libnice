defmodule ExLibnice.IntegrationTest do
  use ExUnit.Case, async: true

  test "ice-trickle" do
    {:ok, tx_pid} = ExLibnice.Support.TestPeer.start_link(self())
    {:ok, rx_pid} = ExLibnice.Support.TestPeer.start_link(self())

    :ok = ExLibnice.Support.TestPeer.set_peer(tx_pid, rx_pid)
    :ok = ExLibnice.Support.TestPeer.set_peer(rx_pid, tx_pid)

    :ok = ExLibnice.Support.TestPeer.start(tx_pid, true)
    :ok = ExLibnice.Support.TestPeer.start(rx_pid, false)

    assert_receive({^tx_pid, :ready}, 2000)
    assert_receive({^rx_pid, :ready}, 2000)

    :ok = ExLibnice.Support.TestPeer.send(tx_pid)

    assert_receive {^rx_pid, :received}
  end
end
