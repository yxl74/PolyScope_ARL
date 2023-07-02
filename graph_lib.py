__author__    = "Eddy Lee"
__email__     = "yxl74@cse.psu.edu"
__copyright__ = "Copyright (C) 2020 PolyScope Project"
__license__   = "Public Domain"
__version__   = "5.0"
__date__      = "Jan 2021"

import networkx as nx

class Attack_Graph():
	def __init__(self):
		self.g = nx.DiGraph()

	def add_node(self, label, lev):
		#Node ID = Label, has attribute level and type
		if not self.g.has_node(label):
			self.g.add_node(label)
			self.g.nodes[label]["level"] = lev
			#self.g.nodes[label]["type"] = tp

	def add_edge(self, label1, label2, in_weight):
		if not self.g.has_edge(label1, label2):
			self.g.add_edge(label1, label2, weight = in_weight)

	def write_graph(self,path):
		nx.write_graphml(self.g, path)


	#returns dictionary of nodes--> centrality value
	#since this is directed graph this calculate in-degree eigenvector centrality
	def centrality(self):
		return nx.eigenvector_centrality(self.g, weight = 'weight' ,max_iter=10000)
	def reverse_centrality(self):
		return nx.eigenvector_centrality(self.g.reverse(), weight='weight', max_iter=10000)
     