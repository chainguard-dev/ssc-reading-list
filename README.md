# Software Supply-Chain Security Reading List

A reading list for software supply-chain security.


Policy
======

-   [NIST 800-218](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf): The Secure Software Development Framework
    -   [I Read NIST 800-218 So You Don't Have To](https://blog.chainguard.dev/i-read-nist-800-218-so-you-dont-have-to-heres-what-to-watch-out-for/) (Chainguard)

-   [Executive Order 14028](https://www.nist.gov/itl/executive-order-improving-nations-cybersecurity) (The White House)

-   [Dependency Issues: Solving the World's Open-Source Software Security Problem](https://warontherocks.com/2022/05/dependency-issues-solving-the-worlds-open-source-software-security-problem/) (War on the Rocks)

-   [Breaking trust: Shades of crisis across an insecure software supply chain](https://www.atlanticcouncil.org/in-depth-research-reports/report/breaking-trust-shades-of-crisis-across-an-insecure-software-supply-chain/) (Atlantic Council)

-   [Securing the Digital Commons: Open-Source Software Cybersecurity](https://science.house.gov/hearings/securing-the-digital-commons-open-source-software-cybersecurity) (US House Committee on Science, Space, and Technology)

Incidents/Threats
=================

-   [kik, left-pad, and npm](https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm.html) (NPM blog)

-   [Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks](https://link.springer.com/chapter/10.1007/978-3-030-52683-2_2) (DIMVA20)

-   [Towards Using Source Code Repositories to Identify Software Supply Chain Attacks](https://dl.acm.org/doi/abs/10.1145/3372297.3420015?casa_token=YSsIGn2lAgUAAAAA:JKARdg_D0tPS1PerolfMMlhosOx-kbOMpcTqu6tn57rV9BGHbsacw03ORONpRclJ6yhkasajuYl2) (SIGSAC20): identifying published software packages with different code from published source

-   [Software Supply Chain Compromises - A Living Dataset](https://github.com/IQTLabs/software-supply-chain-compromises)
    -   [Related paper](https://www.usenix.org/system/files/login/articles/login_winter20_17_geer.pdf)
    -   [CNCF Dataset of incidents](https://github.com/cncf/tag-security/tree/main/supply-chain-security/compromises)

-   [Thesis on typosquatting that made headlines](https://incolumitas.com/data/thesis.pdf). This dude pwn'ed (or could have!) thousands of machines.

-   [Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages](https://arxiv.org/abs/2002.01139)

-   [Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) - So-so writing but a brilliant (and copycatted) attack vector

-   [Log4j described in Wired](https://www.wired.com/story/log4j-flaw-hacking-internet/)

Solutions
=========

-   [In-toto](https://in-toto.io/): specify your full software supply chain as a series of "steps," and verify the integrity of each step
    -   [In-toto: Providing farm-to-table guarantees for bits and bytes](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias) (USENIX Security 19)

-   [Supply-chain Levels for Software Artifacts (SLSA)](https://slsa.dev/): "levels" of security for the supply-chain of a project (e.g., higher levels require 2-party code review for every commit)

-   [The Update Framework](https://theupdateframework.io/): a set of best practices for distributing software packages and other artifacts
    -   [Package Management Security](https://theupdateframework.io/papers/package-management-security-tr08-02.pdf?raw=true) (University of Arizona)
    -   [A Look in the Mirror: Attacks on Package Managers](https://theupdateframework.io/papers/attacks-on-package-managers-ccs2008.pdf?raw=true) (CCS08): catalog of attacks on package managers
    -   [Survivable Key Compromise in Software Update Systems](https://theupdateframework.io/papers/survivable-key-compromise-ccs2010.pdf?raw=true) (CCS10): paper that introduces TUF
    -   [Diplomat: Using Delegations to Protect Community Repositories](https://theupdateframework.io/papers/protect-community-repositories-nsdi2016.pdf?raw=true) (NSDI16): let authors of packages sign the packages, rather than having the repo do it for them
    -   [Mercury: Bandwidth-Effective Prevention of Rollback Attacks Against Community Repositories](https://theupdateframework.io/papers/prevention-rollback-attacks-atc2017.pdf?raw=true) (ATC17): some tricks for saving bandwidth

-   [Sigstore](https://www.sigstore.dev/): allows signing artifacts with [OIDC identities](https://openid.net/connect/) (e.g., "Log in with Facebook")
    -   [Supply Chain Integrity, Transparency, and Trust](https://datatracker.ietf.org/doc/html/draft-birkholz-scitt-architecture-00.html): proposed IETF standard (uses some similar tech to Sigstore)

-   [Software Bill of Materials (SBOM)](https://www.cisa.gov/sbom) (CISA): a list of ingredients that make up software components
    -   [CycloneDX](https://cyclonedx.org/): an SBOM specification
    -   [SPDX](https://spdx.dev/): an SBOM specification

-   [Common Vulnerabilities and Exposures Database](https://www.cve.org/) (MITRE)
    -   [Snyk Vulnerability Scanner](https://snyk.io/learn/vulnerability-scanner/) (Snyk)
    -   [Trivy Vulnerability Scanner](https://aquasecurity.github.io/trivy/v0.27.1/) (Aqua Security)
    -   [Grype Vulnerability Scanner](https://github.com/anchore/grype) (Anchore)
    -   [All About That Base Image](https://uploads-ssl.webflow.com/6228fdbc6c97145dad2a9c2b/624e2337f70386ed568d7e7e_chainguard-all-about-that-base-image.pdf): run vulnerability scanner over common container "base images"

-   Static analysis
    -   [Supporting the Detection of Software Supply Chain Attacks through Unsupervised Signature Generation](https://arxiv.org/abs/2011.02235) (arXiv)

-   [Secure Production Identity Framework for Everyone (SPIFFE)](https://spiffe.io/): PKI for your organization
    -   [SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/): implementation of SPIFFE

-   [Tekton Chains](https://tekton.dev/docs/chains/): artifact signatures and attestations for Tekton CI pipelines

Organizations
=============

-   [Open Software Security Foundation](https://openssf.org/) (OpenSSF)
    -   [Alpha-Omega Project](https://openssf.org/community/alpha-omega/): find and fix vulnerabilities in OSS, and improve project security
    -   [Working groups](https://openssf.org/community/openssf-working-groups/)
        -   Identifying Security Threats in Open Source Projects
        -   Best Practices for Open Source Developers
        -   Securing Critical Projects
        -   Security Tooling
        -   Supply Chain Integrity
        -   Vulnerability Disclosures
        -   Securing Software Repositories

-   [Cloud Native Computing Foundation](https://www.cncf.io/) (CNCF)
    -   Parent of TUF and in-toto (see above)
    -   [Technical Advisory Group on Security](https://github.com/cncf/tag-security) (TAG security)

Background
==========

-   [Reflections on Trusting Trust](https://www.cs.cmu.edu/~rdriley/487/papers/Thompson_1984_ReflectionsonTrustingTrust.pdf)

-   [Transparency logs](https://transparency.dev/): tamper-evident logs of data
    -   [Certificate Transparency](https://dl.acm.org/doi/fullHtml/10.1145/2659897?casa_token=WUWU20zV90gAAAAA:HMEtIURfaQFCRRnvpr09dz9tE-NLZ0cVYCWDK7LNN_4RxnCPoTQpLPshOQj-breDxmVuF5-JofeP) (Communications of the ACM)
    -   [Certificate Transparency](https://developer.mozilla.org/en-US/docs/Web/Security/Certificate_Transparency) (Mozilla)
    -   [Merkle trees](https://blog.ethereum.org/2015/11/15/merkling-in-ethereum/) (Ethereum Foundation)
    -   [Verifiable data structures](https://transparency.dev/verifiable-data-structures/) (Google)
    -   [How CT works](https://certificate.transparency.dev/howctworks/) (Google)

Reports and summaries
=====================

-   [Another reading list](https://github.com/chughes757/SecureSoftwareSupplyChain): lots of overlap with this one

-   [Top Five Challenges in Software Supply Chain Security: Observations From 30 Industry and Government Organizations](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9740718&casa_token=uvuXkVAeGd0AAAAA:1qRdbyDo4wpb12N6Xu0Oxo92Wj9Quuy1eLIypdOqdGiasnbVHvX4eq7rBE7SA90Ib_br-5y6&tag=1) (IEEE S&P22)

-   [State of the Software Supply Chain](https://www.sonatype.com/hubfs/Q3%202021-State%20of%20the%20Software%20Supply%20Chain-Report/SSSC-Report-2021_0913_PM_2.pdf?hsLang=en-us) (Sonatype)

-   [The Secure Software Factory](https://acrobat.adobe.com/link/review?uri=urn%3Aaaid%3Ascds%3AUS%3Ad35dcd5d-b284-381a-a948-0478460c7e4c#pageNum=6) (CNCF)
    -   [Software Supply Chain Security Best Practices](https://project.linuxfoundation.org/hubfs/CNCF_SSCP_v1.pdf) (CNCF): its predecessor
