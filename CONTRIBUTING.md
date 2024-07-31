# Contributing Guidelines

Contributions of any kind are warmly welcomed.

You can contribute with reviews, fixes, improvements, optimizations, enhancements, validation tasks, documentation (usage, design, methodology...), tooling...

Suggested contributions:

- Port on at least one Linux platform.

## Team organization

- [Tnomogna](https://github.com/tnomogna): Code Owner and Development Lead

## How To Contribute

For any contribution to this project, you should:

- Submit an issue describing your proposed contribution
- Wait for a feedback from the code owner and agree with him on the "what" and "how" to produce it
- Fork the repository, develop, test, review and santize your contribution
- Submit a pull request to have your contribution validated, integrated in the main branch and published.

Contributions must comply with a few good practices and common-sense rules to keep the code as readable and maintainable as possible.

The design and implementation can be challenged and modified, but with performances, efficiency and code quality in mind.

The existing code style and coding rules must be followed when fixing, modifying the existing code base.

## Elements Of Design And Implementation

HA-Bench is developped with an object-oriented approach using C++ and C code. It is based on the Luna Universal Client PKCS#11 library. It does not rely on any third-party component.

The main objects used by HA-Bench are:

- The scenario context class

- The scenarii classes

- The test classes

A scenario context allows to share information among a set of scenario instances (of the same kind or not).

A scenario class implements the logic of a use-case that runs several test instances of the same class (typically several instances of a Milenage authentication test). It provides a mean to share information among a set of tests instances of the same kind. The behavior of a scenario can be specialized using scenario-specific flags that are interpreted and used by the scenario and its tests. All the scenario classes implement the same state automata.  

A test class implements the basic behavior of a use-case. It does so using the cryptographic functions of a set of Luna appliances accessed through the Universal Client PKCS#11 library. All the tests of a scenario are running exactly the same code, but in separate threads. Tests instances are not supposed to interact which others: they are running concurrently. However, they can share some data and a context prepared by the scenario instance that manages them. The scenario instance is in charge of the setup of the scenario and of the orchestration of the test activities (prepare, initialize, start and stop the tests in a coordinated manner). All the test classes implement the same state automata.

Some design and implementations principles are applied to improve overall performances:

- Luna HA-Bench is mutex-free.

- State automata are defined to synchronize scenario and test automata (typically to ensure that all tests are started after a proper preparation and initialization sequence of the scenario itself and of all the tests linked to it).

## Code style and quality

Code is produced using common C/C++ code style (see [here](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)).

Code can be edited using [Visual Studio Code](https://code.visualstudio.com/download). It is pretty-printed using the [Better C++ Syntax"](https://marketplace.visualstudio.com/items?itemName=jeff-hykin.better-cpp-syntax) extension of Visual Studio Code.

Code style presentation rules are enhanced with the following rules:

- Use of long identifiers to help cognitive efforts and reduce the need for embedded comments.

- One parameter per line on function declarations and calls.

Code quality is checked using:

- Embedded assertions (that are checked even in release mode without any impact on the functions requiring raw performances).

- Sanitization flags (that are set only when debugging the application).

- SAST tools:

  - Coverity

    - Use of agressive mode.

    - No use of any coding style (MISRA...).

  - Sonarqube

    - The following issues are deliberately ignored:

      - c:CommentedCode / cpp:CommentedCode
        - Description: "Sections of code should not be commented out"
        - Rationale:
          - Comments are always considered as useful, including for presentation formatting purposes.

      - c:PPIncludeNotAtTop / cpp:PPIncludeNotAtTop
        - Description: "#include directives in a file should only be preceded by other preprocessor directives or comments"
        - Rationale:
          - This rule raises some issues with "extern C" statements.

      - c:SingleGotoOrBreakPerIteration / cpp:SingleGotoOrBreakPerIteration
        - Description: "Loops should not have more than one "break" or "goto" statement"
        - Rationale:
          - This is a recommendation to improve code readibility; however, it it sometimes relevant to infringe this rule.

      - S107 / cpp:S107

        - Description: "Functions should not have too many parameters"
        - Rationale:
          - This is a recommendation to manage code complexity; however, it it sometimes relevant to infringe this rule.

      - S134 / cpp:S134
        - Description: "Control flow statements "if", "for", "while", "switch" and "try" should not be nested too deeply"
        - Rationale:
          - This is a recommendation to manage code complexity; however, it it sometimes relevant to infringe this rule.

      - S859 / cpp:S859
        - Description: "A cast shall not remove any const or volatile qualification from the type of a pointer or reference"
        - Rationale:
          - This rule is relevant but raises too many alerts with the PKCS#11 API.

      - S1199 / cpp:S1199
        - Description: "Nested code blocks should not be used"
        - Rationale:
          - This is sometimes required to solve some compilation warnings when all the declarations are not grouped at the beginning of the main section.

      - cpp:S1231
        - Description: "C-style memory allocation routines should not be used"
        - Rationale:
          - This is sometimes required when using C code in C++ code.

      - cpp:S1699
        - Description: "Constructors and destructors should only use defined methods and fields"
        - Rationale:
          - Sometimes, it's relevant to infringe this rule to overcome some C++ limits.

      - S1820 / cpp:S1820
        - Description: "Structures should not have too many fields"
        - Rationale:
          - This is a recommendation to manage code complexity; however, it it sometimes simpler to have less code to write and maintain, even if it infringes this rule, rather than extending the size of the code.

      - S1905 / cpp:S1905
        - Description: "Redundant casts should not be used"
        - Rationale:
          - This is a recommendation to improve code readibility; however, explicit casting helps to reduce cognitive efforts.

      - cpp:S3656
        - Description: "Member variables should not be "protected""
        - Rationale:
          - This recommendation results in too much complexity while not reducing significantly risks for errors.

      - S3776 / cpp:S3776
        - Description: "Cognitive Complexity of functions should not be too high"
        - Rationale:
          - This is a recommendation to manage code complexity; however, it it sometimes simpler to have less code to write and maintain, even if it infringes this rule, rather than extending the size of the code.

      - cpp:S4963
        - Description: "The "Rule-of-Zero" should be followed"
        - Rationale:
          - Sometimes, default destructors cannot be used because they are too large and thus, thei are rejected at compilation time.

      - cpp:S5008
        - Description: ""void *" should not be used in typedefs, member variables, function parameters or return type"
        - Rationale:
          - /

      - S5028 / cpp:S5028
        - Description: "Macros should not be used to define constants"
        - Rationale:
          - /

      - cpp:S5945
        - Description: "C-style array should not be used"
        - Rationale:
          - /

Code is validated using a simple test sequence implemented in 'tests/run-basic-ha-bench-test.sh'. That sequence must not report any error.
