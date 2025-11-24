# egui headstash : front end tools

```

- keep things flexible and organized in grids that react to window format


- use authenticators: iframe window/prewired application extensions/windows for authenticator support:
  - smart-account powered tx signing via non_crititical_extension preparation and injection ( x/402 authentication,webauthn / passkey / bls12-381 / etc)

- user actions should have hooks: since we expect to have stateful things happening when user clicks on instance (like stateful queries spefici to results of actions chosen), we can wire in query hooks to the client middleware for retrival of data related to spefic instance, and also use caching for storage of this data and extremely effecieve applicatoin

- main view shows verified deployed contract instances, search bar for manual contract input and saving to localstorage. once contract instance is selected query for retrieving active market objects to display in list occurs, render infusion instances for users to select to interact with
- tab for displaying registered authenticators for an account (indexerquery,chainfallback)
- tab for registering authenticator (via known ones, or manually via known tx steps take (instantiate+register || upload+instanitate+register))
- tab for using authenticator: (calling smart contract state genericlly)
# human notes
- queries headstash registry for list of all active headstsh (indexer priority chain contract callback)
- Current headstash: table grid wired into queries of all current headstashes
- Create headstash: tab with form to register new headstash
- Interacting with headstash: viewed when selected a headstash, dedicated information regarding global headtash metrics, specific to wallet connected as well, actions for interacting with headsatsh
- bluetooth / 2fa / passkey / auth app support
- penumbra wallet view and client sdk implementati9on
```

### Front End DashBoard: Headstash

- **layer-climb-core**: Full-featured QueryClient with middleware system already implemented
- **AppClient**: Wraps QueryClient with network management and gRPC/REST fallback
- **Smart Account Authentication**: Fully implemented with ETH offline signer integration
- **Chain Registry**: Network configuration management with multi-environment support
- **Wallet Integration**: Complete wallet connection and transaction signing capabilities
  - retrieve data from & and snap cosmos wallet window to ront for seamless experience for wallet use between windows
  - native account offline signing: metamask, keplr phantom, ledger, penumbra wallet, others
  - js-bindgen for app comms with wallet in windows.
  - switch for smart-account authentication use: implement support for defining dedicated smart account id and specification injection for signing actions.

## Requirements Clarification

### What We're Building

1. **reusable Window Components egui:**

- **Easy-to-use egui macros and traits for proof/chain/vm client UIs** macro derived components: modular middleware, indexer,authentication,client defintions per window, for modular definition of new windows we want to wrap into access of global app layer integrated with wallets wasm-bingen statefulness,  modular wallet-powered window support
    - drect smart contract ypes will be used for queries entrypoints: because we are in rust, we will use smart contract query definitions encoded directly to vec for protobuf serialization support, for queries and actions.

2. **Smart Account Authentication Manager**

- register,manage,use authentication via smart_account panel
- view authenticators: use smart account service to query connected wallets registered accounts for authentication
- integration for template authenticators
- visualize authenticator widget appropriately with respect to their recursive definition: `AllOf`,`AnyOf`,`AnyOfBlend` are able to be configured for authenticators, so front end should register/visualize this when registreing authetnicators in a intuitive manner so that we can depyct the layers of authenitcation in a neat manner.  this should eb done in th emodules where th parameter forms will be for each authenticator being added, and also as a review chart underneath for viusal ques of confirmation of layerout and structure.

3. 1-click decentralization support:

4. **Zk-Headstash** Airdrop Distribution Portal

## egui: web-control panel

### Cosmos Clients Specification: Layer-Climb

### Chain & Indexer Config

- define chain & indexerconfigs statically
- prioritize indexer query, fallback manual chain rpc via middleware support
- canonical template for defining knwon chains, contracts, app-frameworks

### Headstash Marketplace

### Template Macro Defintions

### Sovereign Authentication And Custody Support

#### Authenticator Panel

### metamask snaps: metamask plugin

- generates hash to curve for pallas field & proof in metamask wallet
- simple install for metamask snaps, publicly accountably trustless code

### development libraries: js,rust,python
