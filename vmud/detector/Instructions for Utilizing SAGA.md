### List of document

- `executable`：Executable Files for Various Architectures
- `config.properties`：Configuration file
- `SAGACloneDetector.jar`和`SAGACloneDetector-small.jar`：Entries

### Configuration file description：

The following only introduces the modifiable parameters related to vmud.

- `language`：The type of source files(java, c, cpp, py, js, go, common)
- `threshold`：The threshold of clone detection(0 ~ 1)
- `extensions`： The comma-separated file suffixes
- `exe`：The path of executable file
- `granularity`:The detection granularity, including file, method, snippet
- `min-line`:The minimum line number of a method
- `mlcc`:  The minimum token number of a snippet

### Process

- After modifying `config.properties` according to the instructions of the above parameters, you can run vmud, according to the [instructions](../index.md), The relevant running logic is embedded in the vmud.
- If you want to run the SAGA separately, you only need to modify the configuration file and run the `java -jar ./SAGACloneDetector.jar repoDir` command, where repoDir represents the path of the project that requires clone detection.
