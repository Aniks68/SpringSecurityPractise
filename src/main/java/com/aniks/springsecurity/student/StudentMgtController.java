package com.aniks.springsecurity.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentMgtController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Chukwusimdi Okose"),
            new Student(2, "Ekene Ugwu"),
            new Student(3, "Angelus Achi"),
            new Student(4, "Fabio Nwagbo"),
            new Student(5, "Kayode Akindele")
    );

//  These are used with @PreAuthorize annotation through the use of the following keys:    hasRole('ROLE_')  hasAnyRole('ROLE_', 'ROLE_')    hasAuthority('permission')  hasAnyAuthority('permission', 'permission')
    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerStudent(@RequestBody Student student) {
        System.out.println("Register request: " + student);
    }

    @PutMapping(path = "{id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable(value = "id") Integer id, Student student) {
        System.out.println(String.format("%s %s", id, student));
    }

    @DeleteMapping(path = "{id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable(value = "id") Integer id) {
        System.out.println("Deleting student: " + id);
    }

    @GetMapping(path = "{id}")
    @PreAuthorize("hasAuthority('student:read')")
    public Student getStudentById(@PathVariable(value = "id") Integer id, Student student) {
        return STUDENTS.stream()
                .filter(student1 -> student1.getStudentId().equals(id))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Ogaaaa! Student " + id + " does not exist o!"));
    }
}
