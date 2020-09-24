defmodule ElixirLibnice.BundlexProject do
  use Bundlex.Project

  def project do
    [
      natives: natives()
    ]
  end

  defp natives() do
    [
      native: [
        sources: ["native.c"],
        deps: [unifex: :unifex],
        pkg_configs: ["nice"],
        libs: ["pthread"],
        interface: :cnode,
        preprocessor: Unifex
      ]
    ]
  end
end
