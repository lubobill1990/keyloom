import type { ElectrobunConfig } from "electrobun";

export default {
  app: {
    name: "Keyloom",
    identifier: "io.github.lubobill1990.keyloom",
    version: "0.1.0",
  },
  build: {
    useAsar: false,
    bun: { entrypoint: "src/bun/index.ts" },
    copy: {
      "dist/index.html": "views/mainview/index.html",
      "dist/assets": "views/mainview/assets",
      "dist/licenses": "licenses",
      "LICENSE": "licenses/Keyloom.txt",
      "backend/dist/keyloom": "backend",
    },
    watchIgnore: ["dist/**", "backend/**"],
    win: { bundleCEF: false, icon: "assets/brand/icon.ico" },
    mac: { bundleCEF: false },
    linux: { bundleCEF: false },
  },
  scripts: { postBuild: "scripts/post-build.ts" },
} satisfies ElectrobunConfig;
