(function() {var implementors = {};
implementors['tempfile'] = ["impl <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/std/ffi/c_str/struct.CString.html' title='std::ffi::c_str::CString'>CString</a>","impl <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/std/ffi/os_str/struct.OsString.html' title='std::ffi::os_str::OsString'>OsString</a>","impl <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/std/path/struct.PathBuf.html' title='std::path::PathBuf'>PathBuf</a>","impl&lt;'mutex, T&gt; <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/std/sync/mutex/struct.MutexGuard.html' title='std::sync::mutex::MutexGuard'>MutexGuard</a>&lt;'mutex, T&gt; <span class='where'>where T: ?<a class='trait' href='http://doc.rust-lang.org/nightly/core/marker/trait.Sized.html' title='core::marker::Sized'>Sized</a></span>","impl&lt;'rwlock, T&gt; <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/std/sync/rwlock/struct.RwLockReadGuard.html' title='std::sync::rwlock::RwLockReadGuard'>RwLockReadGuard</a>&lt;'rwlock, T&gt; <span class='where'>where T: ?<a class='trait' href='http://doc.rust-lang.org/nightly/core/marker/trait.Sized.html' title='core::marker::Sized'>Sized</a></span>","impl&lt;'rwlock, T&gt; <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/std/sync/rwlock/struct.RwLockWriteGuard.html' title='std::sync::rwlock::RwLockWriteGuard'>RwLockWriteGuard</a>&lt;'rwlock, T&gt; <span class='where'>where T: ?<a class='trait' href='http://doc.rust-lang.org/nightly/core/marker/trait.Sized.html' title='core::marker::Sized'>Sized</a></span>","impl&lt;'mutex, T&gt; <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/std/sys_common/remutex/struct.ReentrantMutexGuard.html' title='std::sys_common::remutex::ReentrantMutexGuard'>ReentrantMutexGuard</a>&lt;'mutex, T&gt;","impl <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/std/sys_common/wtf8/struct.Wtf8Buf.html' title='std::sys_common::wtf8::Wtf8Buf'>Wtf8Buf</a>","impl&lt;T&gt; <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/alloc/boxed/struct.Box.html' title='alloc::boxed::Box'>Box</a>&lt;T&gt; <span class='where'>where T: ?<a class='trait' href='http://doc.rust-lang.org/nightly/core/marker/trait.Sized.html' title='core::marker::Sized'>Sized</a></span>","impl&lt;'a, B&gt; <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='enum' href='http://doc.rust-lang.org/nightly/collections/borrow/enum.Cow.html' title='collections::borrow::Cow'>Cow</a>&lt;'a, B&gt; <span class='where'>where B: <a class='trait' href='http://doc.rust-lang.org/nightly/collections/borrow/trait.ToOwned.html' title='collections::borrow::ToOwned'>ToOwned</a> + ?<a class='trait' href='http://doc.rust-lang.org/nightly/core/marker/trait.Sized.html' title='core::marker::Sized'>Sized</a></span>","impl <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/collections/string/struct.String.html' title='collections::string::String'>String</a>","impl&lt;T&gt; <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/alloc/rc/struct.Rc.html' title='alloc::rc::Rc'>Rc</a>&lt;T&gt; <span class='where'>where T: ?<a class='trait' href='http://doc.rust-lang.org/nightly/core/marker/trait.Sized.html' title='core::marker::Sized'>Sized</a></span>","impl&lt;T&gt; <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='http://doc.rust-lang.org/nightly/collections/vec/struct.Vec.html' title='collections::vec::Vec'>Vec</a>&lt;T&gt;","impl <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='tempfile/struct.NamedTempFile.html' title='tempfile::NamedTempFile'>NamedTempFile</a>",];implementors['serde'] = ["impl&lt;'a&gt; <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='serde/bytes/struct.Bytes.html' title='serde::bytes::Bytes'>Bytes</a>&lt;'a&gt;","impl <a class='trait' href='http://doc.rust-lang.org/nightly/core/ops/trait.Deref.html' title='core::ops::Deref'>Deref</a> for <a class='struct' href='serde/bytes/struct.ByteBuf.html' title='serde::bytes::ByteBuf'>ByteBuf</a>",];

            if (window.register_implementors) {
                window.register_implementors(implementors);
            } else {
                window.pending_implementors = implementors;
            }
        
})()
