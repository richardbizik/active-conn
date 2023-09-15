# eBPF tcp (ipv4) open connection monitoring

# Compile C sources into eBPF bytecode and generate Go bindings
```bash
go generate
```

# install
```bash
go install github.com/richardbizik/active-conn
```

# run (needs to set memlock rlimit hence we run it as a superuser)
```bash
sudo active-conn
```
