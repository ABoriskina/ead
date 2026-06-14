MODE="$1"
cd ..

case "$MODE" in
  c)
      echo "Formatting .c files"
      cd host
      find agent ebpf -type f \( -name "*.c" -o -name "*.h" \) \
        -not -path "*/build/*" \
        -not -name "vmlinux.h" |
      while read -r file; do
          if ! diff -q "$file" <(clang-format "$file") >/dev/null; then
              echo "Reformatted $file"
              clang-format -i "$file"
          fi
      done
      ;;
  go)
      echo "Formatting .go files"
      cd host
      find agent -type f -name "*.go" \
        -not -path "*/build/*" |
      while read -r file; do
          if ! diff -q "$file" <(gofmt "$file") >/dev/null; then
              echo "Reformatted $file"
              gofmt -w "$file"
          fi
      done
      ;;
  py)
      echo "Formatting .py files"
      ./.venv/bin/python -m black analyzer
      ;;
  "")
      echo "Formatting .py files"
      ./.venv/bin/python -m black analyzer
      ;;
esac