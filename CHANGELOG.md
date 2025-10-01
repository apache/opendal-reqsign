# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).

<!-- Release notes generated with: gh release create v_draft --generate-notes --draft -->

## v1.0.0 - 2025-09-01

* chore(deps): Update quick-xml requirement from 0.35 to 0.36 by @dependabot[bot] in https://github.com/Xuanwo/reqsign/pull/456
* feat(azure): implement client secret auth for azure by @twuebi in https://github.com/Xuanwo/reqsign/pull/457
* feat: add Sign trait by @flaneur2020 in https://github.com/Xuanwo/reqsign/pull/459
* chore(deps): Bump google-github-actions/auth from 2.1.3 to 2.1.4 by @dependabot[bot] in https://github.com/Xuanwo/reqsign/pull/461
* ci: Disable azure client secrets test if not set by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/462
* refactor!: remove SignableRequest by @flaneur2020 in https://github.com/Xuanwo/reqsign/pull/463
* fix: readme about signing Parts instead of Request by @flaneur2020 in https://github.com/Xuanwo/reqsign/pull/464
* AWS S3: Add support for assume role duration seconds by @rahull-p in https://github.com/Xuanwo/reqsign/pull/466
* refactor: Remove not needed features by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/468
* docs: correct signer term usage by @jdockerty in https://github.com/Xuanwo/reqsign/pull/469
* Add support for assume role session tags by @rahull-p in https://github.com/Xuanwo/reqsign/pull/470
* refactor: Split into workspace by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/471
* refactor: Split reqsign aws v4 crate by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/472
* refactor: Split reqsign-aliyun-oss crate by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/473
* refactor: Split reqsign-azure-storage by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/474
* chore(deps): Bump google-github-actions/auth from 2.1.4 to 2.1.5 by @dependabot[bot] in https://github.com/Xuanwo/reqsign/pull/475
* refactor: Split google into seperate crate by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/477
* refactor: Split huaweicloud obs to a new crate by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/478
* refactor: Split tencent cos in new crate by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/479
* refactor: Split oracle into seperate crate by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/480
* refactor: Remove not used dep by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/481
* feat: Introduce Signer along with Load/Build/Context by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/482
* chore: Remove not used hash `sha256` by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/483
* feat: Add FileRead and HttpSend by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/484
* chore: Remove tokio from reqsign by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/485
* refactor: Rename to Key to better represents credentails and token by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/486
* feat: Add context in Load and Build by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/487
* feat: Add Env in context by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/488
* refactor(services/aws-v4): Use context env instead by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/489
* refactor: Depends on reqsign-core internally by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/490
* refactor: Split crates into services and context by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/491
* refactor: Make core's API more clear by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/492
* chore(deps): Bump google-github-actions/auth from 2.1.5 to 2.1.6 by @dependabot[bot] in https://github.com/Xuanwo/reqsign/pull/493
* feat: parse endpoint_url from profile and env by @TennyZhuang in https://github.com/Xuanwo/reqsign/pull/497
* chore(deps): Bump google-github-actions/auth from 2.1.6 to 2.1.7 by @dependabot[bot] in https://github.com/Xuanwo/reqsign/pull/496
* chore(deps): Update quick-xml requirement from 0.36 to 0.37 by @dependabot[bot] in https://github.com/Xuanwo/reqsign/pull/495
* refactor: Migrate aws-v4 to new design by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/502
* Percent encoding query params for aliyun OSS by @photino in https://github.com/Xuanwo/reqsign/pull/507
* chore: Address CI by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/510
* fix: Aliyun should not encode query like `start-after` by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/517
* refactor(aliyun): Migrate to reqsign-core based by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/529
* refactor: Migrate azure storage to core based by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/530
* refactor: Use enum for azure credential by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/531
* refactor: Refactor google to core based by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/532
* refactor: Migrate huaweicloud obs to core based by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/533
* refactor: Refactor oracle into core based by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/534
* refactor: Refactor tencent cos to be core based by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/536
* refactor: Ensure to use file_read and env from context by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/537
* refactor: Rename Load to ProvideCredential by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/538
* refactor: Rename Build to SignRequest by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/539
* refactor: Rename Key to SigningCredential by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/540
* docs: Add README and examples for crates by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/541
* refactor: Ensure all credentials are redacted by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/542
* chore(deps): Update windows-sys requirement from 0.59.0 to 0.60.2 by @dependabot[bot] in https://github.com/Xuanwo/reqsign/pull/527
* chore(deps): Update criterion requirement from 0.5 to 0.6 by @dependabot[bot] in https://github.com/Xuanwo/reqsign/pull/521
* chore(deps): Bump google-github-actions/auth from 2.1.7 to 2.1.10 by @dependabot[bot] in https://github.com/Xuanwo/reqsign/pull/520
* refactor: Project Layout  by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/543
* refactor: Allow gcs to support both service account and token by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/544
* refactor: Refactor RawCredential for better names  by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/545
* refactor: Use correct name for filename and fields by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/546
* docs: Update README with new API by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/547
* chore: Cleanup code by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/548
* feat: Add reqsign as wrapper for core by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/549
* refactor: Introduce provide credentail chain for aws v4  by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/550
* refactor: Add credential chain for aliyun oss by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/551
* refactor: Introduce credential chain for azure-storage by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/552
* refactor: Introduce credential chain for google by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/553
* refactor: Introduce credential chain for huaweicloud-obs by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/554
* refactor: Introduce credential chain for oracle and cos by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/555
* feat: Introduce error handling for reqsign  by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/556
* refactor: Split config credential provider into env,profile,static by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/557
* refactor: Remove the concept of config by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/559
* refactor: Polish the API for aws-v4 by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/560
* refactor(services/aliyun): Remove the concept of config by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/561
* refactor(services/azure-storage): Remove the concept of azure-storage by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/562
* chore: Cleanup API design by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/563
* refactor(google): Remove the config concept by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/564
* refactor(services): Remove the config concepts by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/565
* feat: Support coginto, ecs, process, sso provider by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/567
* feat(services/azure): Add AzureCli credential provider by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/568
* feat(services/azure-storage): Add Client Certificate support by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/569
* feat(services/azure-storage): Add Azure Piplelines support by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/570
* chore: Make clippy happy by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/584
* feat: Add s3 express create session support by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/583
* chore: upgrade and tidy dependencies by @tisonkun in https://github.com/Xuanwo/reqsign/pull/588
* refactor: Refactor s3 tests for different providers by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/586
* chore(deps): Bump actions/checkout from 4 to 5 by @dependabot[bot] in https://github.com/Xuanwo/reqsign/pull/589
* refactor: Refactor reqsign error and aws-v4 usage by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/591
* refactor: Return reqsign error instead of anyhow by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/592
* feat: Add CommandExecute in Context by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/593
* feat(services/aws-v4): Add test for s3 express session by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/596
* feat: Add integration tests for azure storage by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/597
* feat(services/aws-v4): Add direct configuration support to ECSCredentialProvider by @jackye1995 in https://github.com/Xuanwo/reqsign/pull/598
* refactor: Add tests for gcs by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/600
* chore: Set all packages version to 1.0 by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/601
* refactor: Implement DefaultContext and DefaultSigner  by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/602
* fix: Update repository URL in Cargo.toml by @kingsword09 in https://github.com/Xuanwo/reqsign/pull/603
* chore(deps): Bump google-github-actions/auth from 2 to 3 by @dependabot[bot] in https://github.com/Xuanwo/reqsign/pull/604
* chore: Using workspace member instead by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/605
* ci: Add release workflow by @Xuanwo in https://github.com/Xuanwo/reqsign/pull/606
