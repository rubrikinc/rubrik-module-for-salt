# Rubrik Salt Module

Rubrik Module for the Salt configuration management tool.

Features the following resources:

* Cluster Info
* Get SLA Domain
* Set SLA Domain
* On-Demand Snapshot
* Register host with Rubrik cluster

# :blue_book: Documentation

Here are some resources to get you started! If you find any challenges from this project are not properly documented or are unclear, please [raise an issue](https://github.com/rubrikinc/rubrik-module-for-salt/issues/new/choose) and let us know! This is a fun, safe environment - don't worry if you're a GitHub newbie! :heart:

* [Quick Start Guide](/docs/quick-start.md)

# :white_check_mark: Prerequisites

* Requires the following Pillar data to be defined for any nodes using the Rubrik module:

```
rubrik.node: rubrik.demo.com
rubrik.username: admin
rubrik.password: Mypass123!
```

* Module should be copied to the `_modules` folder on the Salt master, and distributed to the hosts using the `salt '*' saltutil.sync_all` command

# :muscle: How You Can Help

We glady welcome contributions from the community. From updating the documentation to adding more functions for this module, all ideas are welcome. Thank you in advance for all of your issues, pull requests, and comments! :star:

* [Contributing Guide](CONTRIBUTING.md)
* [Code of Conduct](CODE_OF_CONDUCT.md)

# :pushpin: License

* [MIT License](LICENSE)

# :point_right: About Rubrik Build

We encourage all contributors to become members. We aim to grow an active, healthy community of contributors, reviewers, and code owners. Learn more in our [Welcome to the Rubrik Build Community](https://github.com/rubrikinc/welcome-to-rubrik-build) page.

We'd love to hear from you! Email us: build@rubrik.com :love_letter:
