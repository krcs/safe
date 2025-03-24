$version = "1.0"
$commit = $(git rev-parse HEAD)
$build_date = $(get-date).ToString("yyyyMMdd")

$version = "$version-$build_date-commit:$commit"

go build -ldflags="-X main.AppVersion=$version" -o ./release
