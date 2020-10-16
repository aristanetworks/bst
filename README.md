# bst

bst (pronounced "bestie") is a one-stop shop for running programs
in isolated Linux environments. It is, effectively, a combination
of `unshare`, `mount`, `setarch`, `chroot`, and many others; taking
care of all the low-level minutæ to get in an environment that is
as isolated as possible.

The main purpose of bst is running CI/build processes in a somewhat
deterministic fashion.

## Usage

```
$ bst [options] <exe> <args...>
```

See `man 1 bst` for more detailed information about how to use this
program, including examples.

## Why bst?

While bst is a multi-purpose tool, its main purpose is to serve
as a building block for larger container systems. In CI systems
running lots of commands in rapid succession, the cost of spinning
up Docker containers can be unacceptable. For instance, on an 8-core
laptop, over 10 runs, it takes 1.15 seconds to run `/bin/true` on
an Alpine Linux Docker image, while bst takes 0.07 seconds to setup
and run the same program in an isolated environment.

```
$ perf stat -n -r 10 -- docker run --rm -it alpine true

 Performance counter stats for 'docker run --rm -it alpine true' (10 runs):

            1,1503 +- 0,0156 seconds time elapsed  ( +-  1,36% )

$ perf stat -n -r 10 -- bst -r alpine /bin/true

 Performance counter stats for 'bst -r alpine /bin/true' (10 runs):

           0,07352 +- 0,00470 seconds time elapsed  ( +-  6,40% )
```

bst is not and does not want to be a replacement for Docker, but is
meant to be used by tooling wanting low-overhead isolated environments.

Another strong suit of bst is that, by design, it can be used unprivileged.
bst uses well-defined semantics for user namespaces to give unprivileged
users the rights to enter different environments in a safe and controlled
manner.

## Quickstart

### Installing

There are two ways to install bst: downloading a prepackaged binary, or building from source:

#### Installing a binary package

Go to the [release page](./releases) and download the binary archive of the latest release.

Extract the archive into `/`. bst is installed into /usr/local.

#### Building from source

bst uses [Meson][meson] for its build system (requires python, ninja, sudo, and libcap).
Additionaly, it uses [scdoc][scdoc] to build its man pages.

From the source directory:

```
$ meson ./build
$ ninja -C ./build
$ sudo ninja -C ./build install
```

The last step installs bst into /usr/local.

### Using bst

First, make sure that your current user has a slice of sub-UIDs and sub-GIDs allocated:

```
$ id
uid=1000(barney) gid=1000(barney) groups=1000(barney)

$ grep -H . /etc/sub{u,g}id
/etc/subuid:barney:1000000:65536
/etc/subgid:barney:1000000:65536
```

See `man 5 subuid` and `man 5 subgid` for what these values signify.

Once this is done, you should just be able to try it out:

```
$ bst
# id
uid=0(root), gid=0(root), groups=0(root)
```

[meson]: https://mesonbuild.com
[scdoc]: https://git.sr.ht/~sircmpwn/scdoc
