defmodule ExLibnice.BundlexProject do
  use Bundlex.Project

  def project do
    [
      natives: natives()
    ]
  end

  defp natives() do
    [
      native: [
        sources: ["native.c", "parser.c"],
        deps: [unifex: :unifex],
        os_deps: [nice: :pkg_config],
        interface: [:nif, :cnode],
        preprocessor: Unifex
      ]
    ]
  end
end
