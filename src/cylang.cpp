/* Cycript - The Truly Universal Scripting Language
 * Copyright (C) 2009-2016  Jay Freeman (saurik)
 * Copyright (C)      2016  NowSecure <oleavr@nowsecure.com>
*/

/* GNU Affero General Public License, Version 3 {{{ */
/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
**/
/* }}} */

#include "cylang.h"

#include "Driver.hpp"
#include "Syntax.hpp"

#include <sstream>

char *cylang_compile(const char *code, GError **error) {
	CYPool pool;

	std::stringbuf stream (code);
	CYDriver driver (pool, stream);
	driver.strict_ = false;

	if (driver.Parse () || !driver.errors_.empty ()) {
		for (CYDriver::Errors::const_iterator e (driver.errors_.begin ()); e != driver.errors_.end (); ++e) {
			auto message (e->message_);
			g_set_error_literal (error, CYLANG_COMPILER_ERROR, CYLANG_COMPILER_ERROR_SYNTAX, message.c_str ());
			return NULL;
		}

		g_set_error_literal (error, CYLANG_COMPILER_ERROR, CYLANG_COMPILER_ERROR_SYNTAX, "Compilation failed");
		return NULL;
	}

	g_assert (driver.script_);

	std::stringbuf str;
	CYOptions options;
	CYOutput out (str, options);
	out.pretty_ = true;
	driver.Replace (options);
	out << *driver.script_;

	auto result (str.str());
	return g_strdup (result.c_str ());
}

GQuark cylang_compiler_error_quark(void) {
	return g_quark_from_static_string ("cylang-compiler-error-quark");
}
