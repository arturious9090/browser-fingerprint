import {openStore} from '../database.mjs';
const store=await openStore({dbPath:process.env.DATABASE_PATH});
try{const keyPath=await store.rotateOwner();console.log(`Создан новый ключ владельца: ${keyPath}. Все предыдущие админ-сессии отозваны.`);}finally{store.close();}
