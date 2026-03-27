const fs = require('fs');
const path = require('path');

const srcDir = path.join(__dirname, 'study-hub-react', 'src');
const rootDir = __dirname;

function getAllFiles(dir, extFilter, ignoreList) {
    let results = [];
    if (!fs.existsSync(dir)) return results;
    const list = fs.readdirSync(dir);
    list.forEach(file => {
        const fullPath = path.join(dir, file);
        if (ignoreList.some(i => fullPath.includes(i))) return;
        const stat = fs.statSync(fullPath);
        if (stat && stat.isDirectory()) {
            results = results.concat(getAllFiles(fullPath, extFilter, ignoreList));
        } else {
            if (extFilter.some(ext => file.endsWith(ext))) {
                results.push(fullPath);
            }
        }
    });
    return results;
}

const reactFiles = getAllFiles(srcDir, ['.jsx', '.tsx'], ['node_modules']);
const cssFiles = getAllFiles(srcDir, ['.css'], ['node_modules']);
const legacyFiles = getAllFiles(rootDir, ['.html', '.css', '.js'], ['node_modules', '.git', 'study-hub-react']);

// Find what's imported
let activeReact = new Set(['App.jsx', 'main.jsx']);
let activeCss = new Set(['index.css', 'App.css']);
let allReactContent = '';

reactFiles.forEach(f => {
    allReactContent += fs.readFileSync(f, 'utf8') + '\n';
});

let orphanedReact = [];
let usedLegacy = new Set();
let duplicates = [];

reactFiles.forEach(f => {
    const basename = path.basename(f, path.extname(f));
    if (!activeReact.has(path.basename(f))) {
        // If it's used somewhere else
        // A simple check is if basename appears in other files
        // But let's check properly
        const count = allReactContent.split(basename).length - 1;
        // If it appears more than 1 time (1 is its own definition)
        if (count > 1 || f.includes('pages\\') || f.includes('pages/')) {
            // pages might be dynamically routed
            activeReact.add(path.basename(f));
        } else {
            orphanedReact.push(f);
        }
    }
});

// For duplicates, compare basename of legacy with react base names
legacyFiles.forEach(lf => {
    const lBase = path.parse(lf).name.toLowerCase();
    const lExt = path.parse(lf).ext;
    
    // Check if it's referenced in react
    if (allReactContent.includes(path.basename(lf))) {
        usedLegacy.add(lf);
    }

    reactFiles.forEach(rf => {
        const rBase = path.parse(rf).name.toLowerCase();
        if (lBase === rBase) {
            duplicates.push({legacy: lf, react: rf});
        }
    });
});

let report = "## ACTIVE (Keep - DO NOT TOUCH)\n";
reactFiles.filter(f => activeReact.has(path.basename(f))).forEach(f => report += "- " + path.relative(rootDir, f) + " ✅\n");
cssFiles.forEach(f => report += "- " + path.relative(rootDir, f) + " ✅\n");

report += "\n## LEGACY (Safe to Archive)\n";
legacyFiles.filter(f => !usedLegacy.has(f)).forEach(f => {
    let isDup = duplicates.find(d => d.legacy === f);
    if (!isDup) report += "- " + path.relative(rootDir, f) + " ⚠️\n";
});

report += "\n## DUPLICATES (Need Decision)\n";
duplicates.forEach(d => {
    report += "- " + path.relative(rootDir, d.legacy) + " vs " + path.relative(rootDir, d.react) + "\n";
});

report += "\n## ORPHANED (Unused)\n";
orphanedReact.forEach(f => report += "- " + path.relative(rootDir, f) + "\n");

fs.writeFileSync('analysis-report.md', report);
console.log('Report generated at analysis-report.md');
