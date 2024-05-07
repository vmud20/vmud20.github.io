@main def exec(cpgFile: String,line: Int){
	importCpg(cpgFile)
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).dotPdg.toJson|>"PDG.json"
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).ast.isCall.filter(node=>node.methodFullName=="<operator>.assignment").map(node=>node.lineNumber).toJson|>"assignment.json"
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).ast.isControlStructure.filter(node=>node.controlStructureType=="IF").map(node=>(node.lineNumber)).toJson|>"control.json"
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).ast.isReturn.map(node=>node.lineNumber).toJson|>"return.json"
}
