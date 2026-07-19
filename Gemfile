source "https://rubygems.org"

# Pins Jekyll + plugins to the versions used by the GitHub Pages builder
gem "github-pages", group: :jekyll_plugins

# Windows/JRuby need bundled timezone data
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

gem "wdm", "~> 0.1", platforms: [:mingw, :x64_mingw, :mswin]
gem "webrick", "~> 1.8"
