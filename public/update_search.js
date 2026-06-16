const fs = require('fs');

const filePath = 'index.html';


let content = fs.readFileSync(filePath, 'utf-8');


const headerSearchBtn = `      <button onclick="toggleHeaderSearch()" style="position:relative;display:flex;align-items:center;justify-content:center;color:white;width:36px;height:36px;background:rgba(255,255,255,.15);border-radius:50%;transition:background .2s;border:none;cursor:pointer;" onmouseover="this.style.background='rgba(255,255,255,.25)'" onmouseout="this.style.background='rgba(255,255,255,.15)'" title="Rechercher">
        <span class="material-symbols-outlined" style="font-size:22px;font-variation-settings:'FILL' 0;">search</span>
      </button>
      
      `;


content = content.replace(
  /<button onclick="toggleNotifications/,
  headerSearchBtn + '<button onclick="toggleNotifications'
);


const headerSearch = `
  <div id="headerSearchBar" style="display:none;position:fixed;top:60px;left:0;right:0;background:var(--header-gradient);padding:16px 20px;z-index:49;box-shadow:0 2px 12px rgba(132,0,21,0.3);">
    <div style="max-width:600px;margin:0 auto;position:relative;display:flex;align-items:center;">
      <span class="material-symbols-outlined" style="position:absolute;left:16px;color:rgba(255,255,255,.6);font-size:22px;pointer-events:none;">search</span>
      <input id="headerSearchInput" type="text" placeholder="Rechercher des alertes..." oninput="filtrerAlertesRecherche(this.value)" style="width:100%;height:48px;padding:0 50px 0 50px;background:rgba(255,255,255,.18);border:1.5px solid rgba(255,255,255,.25);border-radius:12px;font-size:14px;color:white;outline:none;transition:all .3s ease;font-family:'Plus Jakarta Sans',sans-serif;box-shadow:inset 0 1px 2px rgba(0,0,0,.15);" onfocus="this.style.background='rgba(255,255,255,.25)';this.style.borderColor='rgba(255,255,255,.5)';this.style.boxShadow='0 4px 20px rgba(0,0,0,.15)';" onblur="this.style.background='rgba(255,255,255,.18)';this.style.borderColor='rgba(255,255,255,.25)';this.style.boxShadow='none';"/>
      <button onclick="closeHeaderSearch()" style="position:absolute;right:14px;background:none;border:none;color:white;opacity:0.7;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:4px;border-radius:50%;transition:opacity .2s;" onmouseover="this.style.opacity='1'" onmouseout="this.style.opacity='0.7'">
        <span class="material-symbols-outlined" style="font-size:24px;">close</span>
      </button>
    </div>
  </div>
`;

content = content.replace(
  /  <\/header>/,
  '  </header>' + headerSearch
);


const searchFunctions = `
    function toggleHeaderSearch() {
      const bar = document.getElementById('headerSearchBar');
      const input = document.getElementById('headerSearchInput');
      if (bar.style.display === 'none') {
        bar.style.display = 'block';
        setTimeout(() => input.focus(), 100);
      } else {
        closeHeaderSearch();
      }
    }

    function closeHeaderSearch() {
      const bar = document.getElementById('headerSearchBar');
      const input = document.getElementById('headerSearchInput');
      bar.style.display = 'none';
      input.value = '';
      filtrerAlertesRecherche('');
    }
`;

content = content.replace(
  /    afficherMenuAdmin\(\);/,
  '    afficherMenuAdmin();' + searchFunctions
);


fs.writeFileSync(filePath, content, 'utf-8');
console.log('✓ Le fichier index.html a été mis à jour avec succès!');
