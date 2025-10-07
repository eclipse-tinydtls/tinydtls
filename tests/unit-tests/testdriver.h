/*******************************************************************************
 *
 * Copyright (c) 2020 Olaf Bergmann (TZI) and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 */

#ifndef _TESTDRIVER_H_
#define _TESTDRIVER_H_

#include <stdio.h>

// A bug fix for an outdated CUnit 2.1-3 that was compiled using a new MSVC
#if _MSC_VER >= 1900
#undef snprintf
#endif

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#endif /* _TESTDRIVER_H_ */
