package lib

import "golang.org/x/net/html"

// listUniqueDataLeaves takes the root of an HTML tree as input and
// outputs an array that contains all the unique leaves of the tree. To
// define if a leaf is unique, the content of the leaf is taken into account.
// The leaves data are ordered from the most right one to the most left one.
//     Example:
//                  R
//                 /|\
//     the tree   A D C   will output [F,D,E]
//               / \   \
//              D   E   F
func listUniqueDataLeaves(root *html.Node) []string {
	leaves := make([]string, 0)
	discovered := make(map[string]bool)
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.FirstChild == nil { // it is a leaf
			if !discovered[n.Data] {
				discovered[n.Data] = true
				leaves = append(leaves, n.Data)
			}

		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(root)
	return leaves
}
