import * as unified from "unified";
import * as markdown from "remark-parse";
import * as fs from "fs";

const file = fs.readFileSync("./README.md");

const tree = unified().use(markdown).parse(file);

const ye: { [key: number]: { heading: any; content: any[] } } = {};
let lastMethodHeadingIndex: number | undefined;
(tree.children as any[]).forEach((node, i) => {
  const { type, depth } = node;
  if (type === "heading" && depth === 3) {
    lastMethodHeadingIndex = i;
    ye[lastMethodHeadingIndex] = {
      heading: node,
      content: [],
    };
  }
  if (i > lastMethodHeadingIndex) {
  }
  return ye;
});

console.log(JSON.stringify(ye, null, 2));
