# CLAUDE.md

- crate layout exists in main readme, reference for orchestration. 
- always complete agentic actions with unit tests verifying changes made are covered for basic sanity/insanity tests
- multi-agent spec making use of git worktrees and ahared todo-files can be invoked using a specif cconfig flag
- make use existing/new deep-wiki mpc dependent on 
- ONLY put api examples in readmes of code logic to prevent tech debt as we iterate code. dont put raw function examples in readme as we agregate documentation for function in the comments of libraries files.
- 99.9% of type defintions are proto defined & generated for cross library compatibility. dont forget pls! this is our ideal setup for maximum modularity