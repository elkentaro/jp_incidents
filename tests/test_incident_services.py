import sqlite3, unittest
import incident_services as services
class Services(unittest.TestCase):
 def setUp(self):
  self.c=sqlite3.connect(':memory:');self.addCleanup(self.c.close)
  self.c.execute('CREATE TABLE incidents(id TEXT PRIMARY KEY,withdrawn INTEGER DEFAULT 0)');self.c.execute("INSERT INTO incidents(id) VALUES('a')");self.c.commit()
 def test_absent_schema_is_readable(self):self.assertEqual(services.read_all(self.c),{})
 def test_scope_is_atomic_and_aliases_require_explicit_confirmation(self):
  services.install(self.c);self.c.commit();self.c.execute('BEGIN')
  services.save(self.c,'a','市民ポータル','https://example.org/notice','市民ポータル affected');self.c.rollback();self.assertEqual(services.get(self.c,'a'),{})
  services.save(self.c,'a','Portal','https://example.org/notice')
  self.assertRaises(ValueError,services.save,self.c,'a','Another Portal','https://example.org/notice')
  services.save(self.c,'a','Renamed Portal','https://example.org/notice','Renamed from Portal',alias=True)
  self.assertTrue(services.matches(services.get(self.c,'a'),'Ｒｅｎａｍｅｄ Ｐｏｒｔａｌ'))
  self.assertEqual(services.label('Organization','Portal'),'Organization : Portal')
 def test_invalid_scope_and_withdrawal(self):
  self.assertRaises(ValueError,services.name,'service');self.assertRaises(ValueError,services.name,'a\nb')
  self.c.execute("UPDATE incidents SET withdrawn=1")
  self.assertRaises(ValueError,services.save,self.c,'a','Portal','https://example.org/notice')
if __name__=='__main__':unittest.main()
