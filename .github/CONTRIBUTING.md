# Contributing to nosco

Thank you for taking interest in `nosco`!

## Found a Bug?

* Please ensure the bug was not already reported by searching the [issue tracker](https://github.com/jamesmth/nosco/issues).
* If you're unable to find an open issue relating to the problem, please file an [issue](https://github.com/jamesmth/nosco/issues/new).

## Want to Submit a Pull Request?

Please ensure your PR follows these guidelines:

### Lint & Formatting

* You used the `rustfmt` coding style for any newly added **Rust** code
* You have ran `clippy` and updated portions of **Rust** code pertaining to your changes

### Documentation & Tests

* You added documentation and possibly doc tests to any new functions or types
* You have updated documentation and doc tests to any modified functions or types as applicable
* You have added tests to cover your changes
* All new and existing tests passed

### Use conventional commits

We use [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) and check for them as
a lint build step. Your commit messages should have enough information to help someone reading the
changelog understand what is new just from the title. The summary helps expand on that to provide
information that helps provide more context, describes the nature of the problem that the commit is
solving and any unintuitive effects of the change. It's rare that code changes can easily
communicate intent, so make sure this is clearly documented.

### Sign your commits

We use commit signature verification, which will block commits from being merged via the UI unless
they are signed. To set up your machine to sign commits, see [managing commit signature
verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
in GitHub docs.

Thanks!
