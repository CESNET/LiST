var lastday = new Date()
lastday.setMonth(lastday.getMonth() - 3);
lastday.setHours(0, 0, 0)
db.alerts_new.deleteMany({DetectTime: {$lt: lastday}});
db.alerts_whitelisted.deleteMany({DetectTime: {$lt: lastday}});
