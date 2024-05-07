@main def exec(cpgFile: String)={
  importCpg(cpgFile)
  cpg.method.toJson|>"method.json"
}
