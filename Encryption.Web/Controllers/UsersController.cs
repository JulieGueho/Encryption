using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using Encryption.Data;

namespace Encryption.Web.Controllers
{
    public class UsersController : Controller
    {
        private Context _context = new Context();

        // GET: /Users/
        public ActionResult Index()
        {
            return View(_context.Users.ToList());
        }

        // GET: /Users/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }

            User user = _context.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }

            return View(user);
        }

        // GET: /Users/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: /Users/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(User user)
        {
            if (ModelState.IsValid)
            {
                _context.Users.Add(user);
                _context.SaveChanges();
                return RedirectToAction("Index");
            }

            return View(user);
        }

        // GET: /Users/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }

            User user = _context.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }

            return View(user);
        }

        // POST: /Users/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include="Id,Firstname,Lastname,KeyVersion,IntegrityChecksum")] User user)
        {
            if (ModelState.IsValid)
            {
                _context.Entry(user).State = EntityState.Modified;
                _context.SaveChanges();
                return RedirectToAction("Index");
            }

            return View(user);
        }

        // GET: /Users/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }

            User user = _context.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }

            return View(user);
        }

        // POST: /Users/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            User user = _context.Users.Find(id);
            _context.Users.Remove(user);
            _context.SaveChanges();
            return RedirectToAction("Index");
        }

        public ActionResult Reset()
        {
            return View();
        }

        [HttpPost, ActionName("Reset")]
        [ValidateAntiForgeryToken]
        public ActionResult ConfirmReset()
        {
            foreach (var user in _context.Users)
            {
                _context.Users.Remove(user);
            }

            _context.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _context.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
