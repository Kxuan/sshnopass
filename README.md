# sshnopass
**THIS PROJECT IS UNDER DEVELOPMENT. USE IT AT YOUR OWN RISK**

This program is used to help you fill password and OTP token to ssh 
automatically.
Only x86-64 platform is supported currently!

## Build
```sh
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

## Configuration
The config file should be placed in `$HOME/.ssh/ssh_auth_config`.
Currently, the config file is really simple. Its format **WILL** changed in the
future.

The first line is your password, and the second line is your otp key.
The otp key is a base32 encoded string.

Example:
```
my_password
my_otp_key
```

## Usage
```
sshnopass command parameters
```
For example:
```
sshnopass ssh root@relay.domain.com
```

## Why not sshpass
The `sshpass` use a pty device to communicate with ssh. it will not work in
some cases, because `sshpass` can not simulate all pty operations like a real 
terminal. And you are unable to avoid passing pty to ssh.

The `sshnopass` use ptrace(2) to "debug" ssh, and communicate with ssh by
hacking its syscall. And once the authentication stage finished, `sshnopass`
detaches ssh.
So the ssh directly communicates with your terminal, you can use all terminal
features.

## Contribute
Feel free to open issues and pull requests using github.

## License
GPLv3
